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
