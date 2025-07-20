use std::collections::HashMap;
use std::fs;
use std::path::Path;
use anyhow::{Result, anyhow};
use log::debug;

/// JSON parsing for container configs
extern crate serde_json;

/// Get container context for a given PID
pub fn get_container_context(pid: u32) -> Result<Option<HashMap<String, String>>> {
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
        
        // Look for kubepods patterns with pod UUID
        if line.contains("kubepods") {
            debug!("Found kubepods line: {}", line);
            
            // Look for pod UUID in kubepods-burstable-pod[UUID].slice format
            if let Some(pod_start) = line.find("kubepods-burstable-pod") {
                let after_pod_prefix = &line[pod_start + "kubepods-burstable-pod".len()..];
                debug!("After 'kubepods-burstable-pod': {}", after_pod_prefix);
                
                if let Some(slice_end) = after_pod_prefix.find(".slice") {
                    let pod_uuid = &after_pod_prefix[..slice_end];
                    debug!("Found pod UUID from kubepods-burstable-pod: {}", pod_uuid);
                    
                    // Validate it looks like a UUID (hex digits and underscores)
                    if is_valid_pod_uuid(pod_uuid) {
                        return create_pod_info_from_uuid(pod_uuid, line);
                    }
                }
            }
            
            // Alternative: look for any pod[UUID].slice pattern
            if let Some(pod_start) = line.find("pod") {
                let after_pod = &line[pod_start + 3..]; // Skip "pod"
                debug!("After 'pod': {}", after_pod);
                
                if let Some(slice_end) = after_pod.find(".slice") {
                    let pod_uuid = &after_pod[..slice_end];
                    debug!("Found pod UUID from pod prefix: {}", pod_uuid);
                    
                    // Validate it looks like a UUID
                    if is_valid_pod_uuid(pod_uuid) {
                        return create_pod_info_from_uuid(pod_uuid, line);
                    }
                }
            }
        }
    }
    
    debug!("No pod info extracted from cgroup");
    None
}

/// Check if a string looks like a valid Kubernetes pod UUID
fn is_valid_pod_uuid(uuid: &str) -> bool {
    // Kubernetes UUIDs are typically 8-4-4-4-12 hex digits separated by underscores
    // Example: 85676363_556c_4ec2_988b_eac1b98fbb66
    uuid.len() >= 20 && 
    uuid.chars().all(|c| c.is_ascii_hexdigit() || c == '_') &&
    uuid.contains('_')
}

/// Create pod info from UUID and cgroup line
fn create_pod_info_from_uuid(pod_uuid: &str, cgroup_line: &str) -> Option<HashMap<String, String>> {
    let mut pod_info = HashMap::new();
    let short_uuid = if pod_uuid.len() >= 8 { &pod_uuid[..8] } else { pod_uuid };
    
    debug!("Creating pod info for UUID: {} (short: {})", pod_uuid, short_uuid);
    
    // Try to map known demo pods based on cgroup line content
    if cgroup_line.contains("demo") || pod_uuid.contains("demo") {
        pod_info.insert("pod_name".to_string(), "demo-target".to_string());
        pod_info.insert("container_name".to_string(), "demo-target".to_string());
    } else if cgroup_line.contains("rasp-controller") || cgroup_line.contains("controller") {
        pod_info.insert("pod_name".to_string(), "rasp-controller".to_string());
        pod_info.insert("container_name".to_string(), "controller".to_string());
    } else if cgroup_line.contains("pod-agent") || cgroup_line.contains("agent") {
        pod_info.insert("pod_name".to_string(), "pod-agent".to_string());
        pod_info.insert("container_name".to_string(), "pod-agent".to_string());
    } else {
        // Generic naming based on UUID
        pod_info.insert("pod_name".to_string(), format!("pod-{}", short_uuid));
        pod_info.insert("container_name".to_string(), "unknown".to_string());
    }
    
    pod_info.insert("namespace".to_string(), "default".to_string());
    pod_info.insert("pod_uuid".to_string(), pod_uuid.to_string());
    
    debug!("Created pod info from cgroup: {:?}", pod_info);
    Some(pod_info)
}