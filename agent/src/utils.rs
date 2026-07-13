use std::collections::HashMap;
use std::fs;
use std::io::ErrorKind;

use anyhow::{anyhow, Result};
use log::debug;

use crate::cache::{get_cache, ProcessKey};

/// JSON parsing for container configs
extern crate serde_json;

/// Get container context for a given PID (with caching)
pub fn get_container_context(pid: u32) -> Result<Option<HashMap<String, String>>> {
    let Some(start_time_ticks) = read_process_start_time(pid)? else {
        return Ok(None);
    };
    let process_key = ProcessKey::new(pid, start_time_ticks);

    // Check cache first
    if let Some(cached) = get_cache().get(process_key) {
        return Ok(cached);
    }

    // Cache miss - perform lookup
    let result = get_container_context_uncached(pid);

    // Confirm the PID still refers to the same process before returning or caching metadata.
    if read_process_start_time(pid)? != Some(start_time_ticks) {
        debug!("Process generation changed while resolving PID {}", pid);
        return Ok(None);
    }

    // Cache the result (including None for non-container processes) for this generation only.
    if let Ok(ref context) = result {
        get_cache().insert(process_key, context.clone());
    }

    result
}

fn read_process_start_time(pid: u32) -> Result<Option<u64>> {
    let stat_path = format!("/proc/{}/stat", pid);
    match fs::read_to_string(&stat_path) {
        Ok(stat) => parse_proc_stat_start_time(&stat).map(Some),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Parse field 22 (`starttime`) from `/proc/<pid>/stat`.
///
/// The command field may contain spaces and closing parentheses, so parsing starts after the
/// final closing parenthesis rather than splitting the complete line on whitespace.
fn parse_proc_stat_start_time(stat: &str) -> Result<u64> {
    const START_TIME_INDEX_AFTER_COMMAND: usize = 19;

    let command_end = stat
        .rfind(')')
        .ok_or_else(|| anyhow!("process stat is missing the command terminator"))?;
    let start_time = stat[command_end + 1..]
        .split_whitespace()
        .nth(START_TIME_INDEX_AFTER_COMMAND)
        .ok_or_else(|| anyhow!("process stat is missing the start time field"))?;

    start_time
        .parse::<u64>()
        .map_err(|error| anyhow!("invalid process start time: {}", error))
}

/// Get container context without caching (internal implementation)
fn get_container_context_uncached(pid: u32) -> Result<Option<HashMap<String, String>>> {
    debug!("Looking up container context for PID: {}", pid);

    // Read cgroup info
    let cgroup_path = format!("/proc/{}/cgroup", pid);
    let cgroup_content = match fs::read_to_string(&cgroup_path) {
        Ok(content) => content,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };

    // Parse container ID from cgroup path
    let container_id = parse_container_id(&cgroup_content)?;
    if container_id.is_empty() {
        return Ok(None); // Not running in a container
    }

    // Read container config
    let config_path = format!("/var/lib/docker/containers/{}/config.v2.json", container_id);
    let config = match fs::read_to_string(&config_path) {
        Ok(content) => content,
        Err(e) => {
            debug!("Failed to read Docker config at {}: {}", config_path, e);
            // Try containerd path
            let containerd_path =
                format!("/run/containerd/containers/{}/config.json", container_id);
            match fs::read_to_string(&containerd_path) {
                Ok(content) => content,
                Err(e2) => {
                    debug!(
                        "Failed to read containerd config at {}: {}",
                        containerd_path, e2
                    );
                    // Try k3s containerd path
                    let k3s_containerd_path = format!(
                        "/var/lib/containerd/containers/{}/config.json",
                        container_id
                    );
                    fs::read_to_string(&k3s_containerd_path).map_err(|e3| {
                        debug!("Failed to read k3s containerd config at {}: {}", k3s_containerd_path, e3);
                        anyhow!("Failed to read container config from Docker ({}), containerd ({}), or k3s containerd ({})", e, e2, e3)
                    })?
                }
            }
        }
    };

    // Parse container config
    let config: serde_json::Value = serde_json::from_str(&config)?;

    let mut context = HashMap::new();
    context.insert("container_id".to_string(), container_id.clone());

    // Extract kubernetes metadata if available
    if let Some(labels) = config.get("Labels").and_then(|l| l.as_object()) {
        if let Some(pod) = labels
            .get("io.kubernetes.pod.name")
            .and_then(|v| v.as_str())
        {
            context.insert("pod_name".to_string(), pod.to_string());
        }
        if let Some(ns) = labels
            .get("io.kubernetes.pod.namespace")
            .and_then(|v| v.as_str())
        {
            context.insert("namespace".to_string(), ns.to_string());
        }
        if let Some(container) = labels
            .get("io.kubernetes.container.name")
            .and_then(|v| v.as_str())
        {
            context.insert("container_name".to_string(), container.to_string());
        }
    } else {
        // Fallback: try to extract pod info from cgroup if config files fail
        debug!("Config file parsing failed, trying cgroup fallback");
        if let Some(pod_info) = extract_pod_info_from_cgroup(&cgroup_content) {
            context.extend(pod_info);
        }
    }

    debug!("Found container context for PID {}: {:?}", pid, context);
    Ok(Some(context))
}

/// Parse container ID from cgroup content
fn parse_container_id(cgroup_content: &str) -> Result<String> {
    debug!("Parsing cgroup content: {}", cgroup_content);

    for line in cgroup_content.lines() {
        debug!("Processing cgroup line: {}", line);

        // Check for k3s containerd format: cri-containerd-{id}.scope
        if line.contains("cri-containerd-") {
            // Extract the container ID between "cri-containerd-" and ".scope"
            if let Some(start) = line.find("cri-containerd-") {
                let after_prefix = &line[start + "cri-containerd-".len()..];
                if let Some(end) = after_prefix.find(".scope") {
                    let container_id = &after_prefix[..end];
                    if container_id.len() >= 12
                        && container_id.chars().all(|c| c.is_ascii_hexdigit())
                    {
                        debug!("Found k3s containerd container ID: {}", container_id);
                        return Ok(container_id.to_string());
                    }
                }
            }
        }

        // Check for standard docker format
        if line.contains("docker") {
            if let Some(id) = line
                .split('/')
                .find(|s| s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()))
            {
                debug!("Found Docker container ID: {}", id);
                return Ok(id.to_string());
            }
        }

        // Check for standard containerd format
        if line.contains("containerd") && !line.contains("cri-containerd") {
            if let Some(id) = line
                .split('/')
                .find(|s| s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()))
            {
                debug!("Found containerd container ID: {}", id);
                return Ok(id.to_string());
            }
        }

        // Fallback: look for any long hex string in kubepods paths
        if line.contains("kubepods") {
            let parts: Vec<&str> = line.split('/').collect();
            for part in parts {
                if part.len() >= 32
                    && part.len() <= 128
                    && part.chars().all(|c| c.is_ascii_hexdigit())
                {
                    debug!("Found potential container ID in kubepods: {}", part);
                    return Ok(part.to_string());
                }
            }
        }
    }
    debug!("No container ID found in cgroup content");
    Ok(String::new()) // Not in a container
}

/// Extract pod info from cgroup content
fn extract_pod_info_from_cgroup(cgroup_content: &str) -> Option<HashMap<String, String>> {
    debug!("Extracting pod info from cgroup content");
    debug!("Full cgroup content: {}", cgroup_content);

    for line in cgroup_content.lines() {
        debug!("Processing cgroup line for pod info: {}", line);

        // Simple approach: look for any UUID pattern with underscores
        // Pattern: 8chars_4chars_4chars_4chars_12chars (like Kubernetes UUIDs)
        let parts: Vec<&str> = line.split('/').collect();
        for part in parts {
            debug!("Checking part: {}", part);

            // Look for parts that contain underscores and look like UUIDs
            if part.contains('_') && part.len() > 20 {
                // Try to extract UUID from patterns like:
                // kubepods-besteffort-pod9e4b6a9_53bb_4666_858d_8c2b128ad18a.slice
                if let Some(uuid_start) = part.find("pod") {
                    let after_pod = &part[uuid_start + 3..];
                    if let Some(slice_pos) = after_pod.find(".slice") {
                        let potential_uuid = &after_pod[..slice_pos];
                        debug!("Found potential UUID: {}", potential_uuid);

                        if potential_uuid.len() > 10 && potential_uuid.contains('_') {
                            let mut pod_info = HashMap::new();
                            let short_uuid = if potential_uuid.len() >= 8 {
                                &potential_uuid[..8]
                            } else {
                                potential_uuid
                            };

                            pod_info.insert("pod_name".to_string(), format!("pod-{}", short_uuid));
                            pod_info.insert("container_name".to_string(), "container".to_string());
                            pod_info.insert("namespace".to_string(), "default".to_string());
                            pod_info.insert("pod_uuid".to_string(), potential_uuid.to_string());

                            debug!("SUCCESS: Created pod info from UUID: {:?}", pod_info);
                            return Some(pod_info);
                        }
                    }
                }

                // Alternative: look for raw UUID patterns (fallback)
                if part.len() > 30 && part.matches('_').count() >= 3 {
                    let uuid_chars: String = part
                        .chars()
                        .filter(|c| c.is_ascii_hexdigit() || *c == '_')
                        .collect();
                    if uuid_chars.len() > 20 {
                        let mut pod_info = HashMap::new();
                        let short_uuid = if uuid_chars.len() >= 8 {
                            &uuid_chars[..8]
                        } else {
                            &uuid_chars
                        };

                        pod_info.insert("pod_name".to_string(), format!("pod-{}", short_uuid));
                        pod_info.insert("container_name".to_string(), "container".to_string());
                        pod_info.insert("namespace".to_string(), "default".to_string());
                        pod_info.insert("pod_uuid".to_string(), uuid_chars);

                        debug!("SUCCESS: Created pod info from raw UUID: {:?}", pod_info);
                        return Some(pod_info);
                    }
                }
            }
        }
    }

    debug!("No pod info extracted from cgroup");
    None
}

#[cfg(test)]
mod tests {
    use super::parse_proc_stat_start_time;

    #[test]
    fn parses_process_start_time() {
        let stat = "123 (worker) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 424242 20";

        assert_eq!(parse_proc_stat_start_time(stat).unwrap(), 424242);
    }

    #[test]
    fn parses_start_time_when_command_contains_spaces_and_parentheses() {
        let stat = "123 (worker) pool) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 99 20";

        assert_eq!(parse_proc_stat_start_time(stat).unwrap(), 99);
    }

    #[test]
    fn rejects_stat_without_command_terminator() {
        assert!(parse_proc_stat_start_time("123 worker S 1 2").is_err());
    }

    #[test]
    fn rejects_stat_without_start_time() {
        assert!(parse_proc_stat_start_time("123 (worker) S 1 2").is_err());
    }
}
