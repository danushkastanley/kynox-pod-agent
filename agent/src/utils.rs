use std::collections::HashMap;
use std::fs;
use std::path::Path;
use anyhow::{Result, anyhow};
use log::debug;

use crate::cache::get_cache;

/// JSON parsing for container configs
extern crate serde_json;

/// Get container context for a given PID (with caching)
pub fn get_container_context(pid: u32) -> Result<Option<HashMap<String, String>>> {
    // Check cache first
    if let Some(cached) = get_cache().get(pid) {
        return Ok(cached);
    }

    // Cache miss - perform lookup
    let result = get_container_context_uncached(pid);

    // Cache the result (including None for non-container processes)
    if let Ok(ref context) = result {
        get_cache().insert(pid, context.clone());
    }

    result
}

/// Get container context without caching (internal implementation)
fn get_container_context_uncached(pid: u32) -> Result<Option<HashMap<String, String>>> {
    debug!("Looking up container context for PID: {}", pid);
    
    // Read cgroup info
    let cgroup_path = format!("/proc/{}/cgroup", pid);
    if !Path::new(&cgroup_path).exists() {
        return Ok(None);
    }

    let cgroup_content = fs::read_to_string(&cgroup_path)?;
    
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
            let containerd_path = format!("/run/containerd/containers/{}/config.json", container_id);
            match fs::read_to_string(&containerd_path) {
                Ok(content) => content,
                Err(e2) => {
                    debug!("Failed to read containerd config at {}: {}", containerd_path, e2);
                    // Try k3s containerd path
                    let k3s_containerd_path = format!("/var/lib/containerd/containers/{}/config.json", container_id);
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
        if let Some(pod) = labels.get("io.kubernetes.pod.name").and_then(|v| v.as_str()) {
            context.insert("pod_name".to_string(), pod.to_string());
        }
        if let Some(ns) = labels.get("io.kubernetes.pod.namespace").and_then(|v| v.as_str()) {
            context.insert("namespace".to_string(), ns.to_string());
        }
        if let Some(container) = labels.get("io.kubernetes.container.name").and_then(|v| v.as_str()) {
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

/// Get comprehensive process context including host processes and control plane components
/// This function is designed to never fail and always return some context
pub fn get_comprehensive_process_context(pid: u32) -> Result<HashMap<String, String>> {
    let mut context = HashMap::new();
    
    // Always add basic process info
    context.insert("pid".to_string(), pid.to_string());
    
    // First try to get container context (this is the most reliable)
    match get_container_context(pid) {
        Ok(Some(container_ctx)) => {
            context.extend(container_ctx);
            context.insert("process_type".to_string(), "containerized".to_string());
        }
        Ok(None) => {
            // This is a host process - try to get host process info
            context.insert("process_type".to_string(), "host".to_string());
            
            // Try to get process info from /proc (don't fail if this doesn't work)
            if let Ok(process_info) = get_host_process_info(pid) {
                context.extend(process_info);
            } else {
                // Even if we can't read process info, add what we can
                context.insert("cmdline".to_string(), format!("unknown_pid_{}", pid));
            }
        }
        Err(_) => {
            // If even container context lookup fails, provide minimal context
            context.insert("process_type".to_string(), "unknown".to_string());
            context.insert("cmdline".to_string(), format!("error_reading_pid_{}", pid));
        }
    }
    
    // Add node information (always available from env)
    if let Ok(node_name) = std::env::var("NODE_NAME") {
        context.insert("node_name".to_string(), node_name);
    } else {
        context.insert("node_name".to_string(), "unknown".to_string());
    }
    
    // Classify the process type (this should never fail now)
    classify_process_type(&mut context, pid);
    
    Ok(context)
}

/// Get information about host processes
/// This function is more robust and handles cases where processes disappear during read
fn get_host_process_info(pid: u32) -> Result<HashMap<String, String>> {
    let mut info = HashMap::new();
    
    // Check if process exists first
    let proc_dir = format!("/proc/{}", pid);
    if !Path::new(&proc_dir).exists() {
        return Err(anyhow!("Process {} no longer exists", pid));
    }
    
    // Read process command line (this is the most reliable)
    let cmdline_path = format!("/proc/{}/cmdline", pid);
    match fs::read_to_string(&cmdline_path) {
        Ok(cmdline) => {
            let clean_cmdline = cmdline.replace('\0', " ").trim().to_string();
            if !clean_cmdline.is_empty() {
                info.insert("cmdline".to_string(), clean_cmdline);
            } else {
                info.insert("cmdline".to_string(), format!("kernel_thread_{}", pid));
            }
        }
        Err(_) => {
            // Process might have disappeared or be a kernel thread
            info.insert("cmdline".to_string(), format!("unavailable_pid_{}", pid));
        }
    }
    
    // Try to read process exe (optional, often fails for kernel threads)
    let exe_path = format!("/proc/{}/exe", pid);
    if let Ok(exe_link) = fs::read_link(&exe_path) {
        if let Some(exe_str) = exe_link.to_str() {
            info.insert("executable".to_string(), exe_str.to_string());
        }
    }
    
    // Try to read process status for additional info (optional)
    let status_path = format!("/proc/{}/status", pid);
    if let Ok(status) = fs::read_to_string(&status_path) {
        for line in status.lines() {
            if line.starts_with("PPid:") {
                if let Some(ppid) = line.split_whitespace().nth(1) {
                    info.insert("parent_pid".to_string(), ppid.to_string());
                }
                break; // We only need PPid
            }
        }
    }
    
    Ok(info)
}

/// Classify process types for better monitoring
fn classify_process_type(context: &mut HashMap<String, String>, pid: u32) {
    if let Some(cmdline) = context.get("cmdline") {
        let lower_cmdline = cmdline.to_lowercase();
        
        // Kubernetes control plane components
        if lower_cmdline.contains("kube-apiserver") {
            context.insert("component_type".to_string(), "kube-apiserver".to_string());
            context.insert("control_plane".to_string(), "true".to_string());
        } else if lower_cmdline.contains("kube-controller-manager") {
            context.insert("component_type".to_string(), "kube-controller-manager".to_string());
            context.insert("control_plane".to_string(), "true".to_string());
        } else if lower_cmdline.contains("kube-scheduler") {
            context.insert("component_type".to_string(), "kube-scheduler".to_string());
            context.insert("control_plane".to_string(), "true".to_string());
        } else if lower_cmdline.contains("etcd") {
            context.insert("component_type".to_string(), "etcd".to_string());
            context.insert("control_plane".to_string(), "true".to_string());
        } else if lower_cmdline.contains("kubelet") {
            context.insert("component_type".to_string(), "kubelet".to_string());
            context.insert("node_agent".to_string(), "true".to_string());
        } else if lower_cmdline.contains("kube-proxy") {
            context.insert("component_type".to_string(), "kube-proxy".to_string());
            context.insert("node_agent".to_string(), "true".to_string());
        } else if lower_cmdline.contains("containerd") {
            context.insert("component_type".to_string(), "containerd".to_string());
            context.insert("container_runtime".to_string(), "true".to_string());
        } else if lower_cmdline.contains("dockerd") {
            context.insert("component_type".to_string(), "dockerd".to_string());
            context.insert("container_runtime".to_string(), "true".to_string());
        }
    }
    
    // For containerized processes, check if they're system pods
    if let Some(namespace) = context.get("namespace") {
        if namespace == "kube-system" || namespace == "kube-public" || namespace == "kube-node-lease" {
            context.insert("system_pod".to_string(), "true".to_string());
        }
    }
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
                    if container_id.len() >= 12 && container_id.chars().all(|c| c.is_ascii_hexdigit()) {
                        debug!("Found k3s containerd container ID: {}", container_id);
                        return Ok(container_id.to_string());
                    }
                }
            }
        }
        
        // Check for standard docker format
        if line.contains("docker") {
            if let Some(id) = line.split('/')
                .find(|s| s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())) {
                debug!("Found Docker container ID: {}", id);
                return Ok(id.to_string());
            }
        }
        
        // Check for standard containerd format  
        if line.contains("containerd") && !line.contains("cri-containerd") {
            if let Some(id) = line.split('/')
                .find(|s| s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())) {
                debug!("Found containerd container ID: {}", id);
                return Ok(id.to_string());
            }
        }
        
        // Fallback: look for any long hex string in kubepods paths
        if line.contains("kubepods") {
            let parts: Vec<&str> = line.split('/').collect();
            for part in parts {
                if part.len() >= 32 && part.len() <= 128 && part.chars().all(|c| c.is_ascii_hexdigit()) {
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
                            let short_uuid = if potential_uuid.len() >= 8 { &potential_uuid[..8] } else { potential_uuid };
                            
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
                    let uuid_chars: String = part.chars().filter(|c| c.is_ascii_hexdigit() || *c == '_').collect();
                    if uuid_chars.len() > 20 {
                        let mut pod_info = HashMap::new();
                        let short_uuid = if uuid_chars.len() >= 8 { &uuid_chars[..8] } else { &uuid_chars };
                        
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