use std::collections::HashMap;
use std::fs;
use std::path::Path;
use anyhow::{Result, anyhow};
use log::debug;

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
            // Try containerd path
            let containerd_path = format!("/run/containerd/containers/{}/config.json", container_id);
            fs::read_to_string(&containerd_path).map_err(|_| {
                anyhow!("Failed to read container config from both Docker and containerd paths: {}", e)
            })?
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
    }

    debug!("Found container context for PID {}: {:?}", pid, context);
    Ok(Some(context))
}

/// Get comprehensive process context including host processes and control plane components
pub fn get_comprehensive_process_context(pid: u32) -> Result<HashMap<String, String>> {
    let mut context = HashMap::new();
    
    // First try to get container context
    if let Ok(Some(container_ctx)) = get_container_context(pid) {
        context.extend(container_ctx);
        context.insert("process_type".to_string(), "containerized".to_string());
    } else {
        // This is a host process
        context.insert("process_type".to_string(), "host".to_string());
        
        // Get process info from /proc
        if let Ok(process_info) = get_host_process_info(pid) {
            context.extend(process_info);
        }
    }
    
    // Add node information
    if let Ok(node_name) = std::env::var("NODE_NAME") {
        context.insert("node_name".to_string(), node_name);
    }
    
    // Classify the process type
    classify_process_type(&mut context, pid);
    
    Ok(context)
}

/// Get information about host processes
fn get_host_process_info(pid: u32) -> Result<HashMap<String, String>> {
    let mut info = HashMap::new();
    
    // Read process command line
    let cmdline_path = format!("/proc/{}/cmdline", pid);
    if let Ok(cmdline) = fs::read_to_string(&cmdline_path) {
        info.insert("cmdline".to_string(), cmdline.replace('\0', " "));
    }
    
    // Read process exe
    let exe_path = format!("/proc/{}/exe", pid);
    if let Ok(exe_link) = fs::read_link(&exe_path) {
        if let Some(exe_str) = exe_link.to_str() {
            info.insert("executable".to_string(), exe_str.to_string());
        }
    }
    
    // Read process status for additional info
    let status_path = format!("/proc/{}/status", pid);
    if let Ok(status) = fs::read_to_string(&status_path) {
        for line in status.lines() {
            if line.starts_with("PPid:") {
                if let Some(ppid) = line.split_whitespace().nth(1) {
                    info.insert("parent_pid".to_string(), ppid.to_string());
                }
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
    for line in cgroup_content.lines() {
        // Check for docker
        if line.contains("docker") {
            if let Some(id) = line.split('/')
                .find(|s| s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())) {
                return Ok(id.to_string());
            }
        }
        // Check for containerd
        if line.contains("containerd") {
            if let Some(id) = line.split('/')
                .find(|s| s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())) {
                return Ok(id.to_string());
            }
        }
    }
    Ok(String::new()) // Not in a container
}
