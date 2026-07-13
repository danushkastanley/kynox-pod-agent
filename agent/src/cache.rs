use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use log::debug;

type ContainerContext = HashMap<String, String>;
type CachedContainerContext = CacheEntry<Option<ContainerContext>>;
type CacheEntries = HashMap<ProcessKey, CachedContainerContext>;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProcessKey {
    pub pid: u32,
    pub start_time_ticks: u64,
}

impl ProcessKey {
    pub fn new(pid: u32, start_time_ticks: u64) -> Self {
        Self {
            pid,
            start_time_ticks,
        }
    }
}

/// Cache entry with expiration time
struct CacheEntry<T> {
    value: T,
    expires_at: Instant,
}

impl<T> CacheEntry<T> {
    fn new(value: T, ttl: Duration) -> Self {
        Self {
            value,
            expires_at: Instant::now() + ttl,
        }
    }

    fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }
}

/// Thread-safe LRU-like cache with TTL support for container metadata
pub struct ContainerCache {
    cache: RwLock<CacheEntries>,
    ttl: Duration,
    max_size: usize,
    // Cache statistics
    stats: RwLock<CacheStats>,
}

#[derive(Default, Clone)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
}

impl CacheStats {
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }
}

impl ContainerCache {
    /// Create a new cache with the specified TTL and maximum size
    pub fn new(ttl: Duration, max_size: usize) -> Self {
        Self {
            cache: RwLock::new(HashMap::with_capacity(max_size)),
            ttl,
            max_size,
            stats: RwLock::new(CacheStats::default()),
        }
    }

    /// Get a cached value for a process generation, returning None if not found or expired.
    pub fn get(&self, key: ProcessKey) -> Option<Option<ContainerContext>> {
        // First try read lock for better concurrency
        let cache = self.cache.read().unwrap();
        if let Some(entry) = cache.get(&key) {
            if !entry.is_expired() {
                // Record hit
                if let Ok(mut stats) = self.stats.write() {
                    stats.hits += 1;
                }
                debug!("Container context cache hit");
                return Some(entry.value.clone());
            }
        }
        // Record miss
        if let Ok(mut stats) = self.stats.write() {
            stats.misses += 1;
        }
        debug!("Container context cache miss");
        None
    }

    /// Insert a value into the cache
    pub fn insert(&self, key: ProcessKey, value: Option<ContainerContext>) {
        let mut cache = self.cache.write().unwrap();

        // Evict expired entries if we're at capacity
        if cache.len() >= self.max_size {
            self.evict_expired(&mut cache);
        }

        // If still at capacity, remove oldest entries (simple eviction)
        if cache.len() >= self.max_size {
            // Remove first 10% of entries to make room
            let to_remove: Vec<ProcessKey> =
                cache.keys().take(self.max_size / 10 + 1).copied().collect();
            for key in to_remove {
                cache.remove(&key);
                if let Ok(mut stats) = self.stats.write() {
                    stats.evictions += 1;
                }
            }
        }

        cache.insert(key, CacheEntry::new(value, self.ttl));
        debug!("Cached container context (cache size: {})", cache.len());
    }

    /// Remove expired entries from the cache
    fn evict_expired(&self, cache: &mut CacheEntries) {
        let expired: Vec<ProcessKey> = cache
            .iter()
            .filter(|(_, entry)| entry.is_expired())
            .map(|(key, _)| *key)
            .collect();

        for key in expired {
            cache.remove(&key);
            if let Ok(mut stats) = self.stats.write() {
                stats.evictions += 1;
            }
        }
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        self.stats.read().unwrap().clone()
    }

    /// Get current cache size
    pub fn len(&self) -> usize {
        self.cache.read().unwrap().len()
    }

    /// Periodic cleanup of expired entries (call this from a background task)
    pub fn cleanup_expired(&self) {
        let mut cache = self.cache.write().unwrap();
        let before = cache.len();
        self.evict_expired(&mut cache);
        let after = cache.len();
        if before > after {
            debug!("Cache cleanup: removed {} expired entries", before - after);
        }
    }
}

/// Global cache instance with default settings
/// TTL: 5 minutes (containers don't change often)
/// Max size: 10000 entries (should be enough for most clusters)
use std::sync::OnceLock;

static CONTAINER_CACHE: OnceLock<ContainerCache> = OnceLock::new();

pub fn get_cache() -> &'static ContainerCache {
    CONTAINER_CACHE.get_or_init(|| ContainerCache::new(Duration::from_secs(300), 10000))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_insert_and_get() {
        let cache = ContainerCache::new(Duration::from_secs(60), 100);
        let key = ProcessKey::new(1234, 100);

        let mut context = HashMap::new();
        context.insert("pod_name".to_string(), "test-pod".to_string());

        cache.insert(key, Some(context.clone()));

        let result = cache.get(key);
        assert!(result.is_some());
        assert_eq!(
            result.unwrap().unwrap().get("pod_name").unwrap(),
            "test-pod"
        );
    }

    #[test]
    fn test_cache_miss() {
        let cache = ContainerCache::new(Duration::from_secs(60), 100);

        let result = cache.get(ProcessKey::new(9999, 100));
        assert!(result.is_none());
    }

    #[test]
    fn test_cache_expiration() {
        let cache = ContainerCache::new(Duration::from_millis(10), 100);
        let key = ProcessKey::new(1234, 100);

        let mut context = HashMap::new();
        context.insert("pod_name".to_string(), "test-pod".to_string());

        cache.insert(key, Some(context));

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(20));

        let result = cache.get(key);
        assert!(result.is_none());
    }

    #[test]
    fn test_cache_stats() {
        let cache = ContainerCache::new(Duration::from_secs(60), 100);
        let key = ProcessKey::new(1234, 100);

        let mut context = HashMap::new();
        context.insert("pod_name".to_string(), "test-pod".to_string());

        cache.insert(key, Some(context));

        // Hit
        cache.get(key);
        // Miss
        cache.get(ProcessKey::new(9999, 100));

        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert!((stats.hit_rate() - 0.5).abs() < 0.001);
    }

    #[test]
    fn does_not_reuse_context_for_a_new_process_generation() {
        let cache = ContainerCache::new(Duration::from_secs(60), 100);
        let old_key = ProcessKey::new(1234, 100);
        let new_key = ProcessKey::new(1234, 200);

        let mut context = HashMap::new();
        context.insert("pod_name".to_string(), "old-pod".to_string());
        cache.insert(old_key, Some(context));

        assert!(cache.get(new_key).is_none());
    }
}
