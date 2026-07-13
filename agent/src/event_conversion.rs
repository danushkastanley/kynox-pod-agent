use std::collections::HashMap;

use agent_core::constants::{
    EVENT_TYPE_ACCEPT, EVENT_TYPE_BIND, EVENT_TYPE_BPF_PROG, EVENT_TYPE_CAPSET, EVENT_TYPE_CHMOD,
    EVENT_TYPE_CONNECT, EVENT_TYPE_EXEC, EVENT_TYPE_FORK, EVENT_TYPE_MOUNT, EVENT_TYPE_OPEN,
    EVENT_TYPE_PTRACE, EVENT_TYPE_SECCOMP, EVENT_TYPE_SETGID, EVENT_TYPE_SETUID, EVENT_TYPE_SOCKET,
    EVENT_TYPE_UMOUNT,
};
use agent_core::EventOutput;
use log::debug;
use prost_types::Timestamp;

use crate::connection::ConnectionManager;
use crate::telemetry::{self, SecurityEvent};
use crate::utils::get_container_context;
use crate::BoxError;

pub fn convert_eventoutput_to_securityevent(
    event: &EventOutput,
    connection: &ConnectionManager,
) -> Result<SecurityEvent, BoxError> {
    debug!(
        "Converting EventOutput (PID: {}) to SecurityEvent",
        event.pid
    );

    let event_type = match event.event_type {
        EVENT_TYPE_EXEC => telemetry::EventType::Exec as i32,
        EVENT_TYPE_OPEN => telemetry::EventType::Open as i32,
        EVENT_TYPE_CONNECT => telemetry::EventType::Connect as i32,
        EVENT_TYPE_FORK => telemetry::EventType::Fork as i32,
        EVENT_TYPE_PTRACE => telemetry::EventType::Ptrace as i32,
        EVENT_TYPE_SETUID => telemetry::EventType::Setuid as i32,
        EVENT_TYPE_SETGID => telemetry::EventType::Setgid as i32,
        EVENT_TYPE_MOUNT => telemetry::EventType::Mount as i32,
        EVENT_TYPE_UMOUNT => telemetry::EventType::Umount as i32,
        EVENT_TYPE_CAPSET => telemetry::EventType::Capset as i32,
        EVENT_TYPE_BPF_PROG => telemetry::EventType::BpfProg as i32,
        EVENT_TYPE_SECCOMP => telemetry::EventType::Seccomp as i32,
        EVENT_TYPE_SOCKET => telemetry::EventType::Socket as i32,
        EVENT_TYPE_BIND => telemetry::EventType::Bind as i32,
        EVENT_TYPE_ACCEPT => telemetry::EventType::Accept as i32,
        EVENT_TYPE_CHMOD => telemetry::EventType::Chmod as i32,
        _ => return Err("Unknown event type".into()),
    };

    let process_context = match get_container_context(event.pid) {
        Ok(context) => context,
        Err(error) => {
            debug!(
                "Failed to resolve container context for PID {}: {}",
                event.pid, error
            );
            None
        }
    };
    let mut container_context = target_context(process_context);
    add_monitoring_identity(&mut container_context, connection);

    if event.event_type == EVENT_TYPE_FORK {
        if let Some(parent_pid) = event.parent_pid.filter(|pid| *pid > 0) {
            if let Ok(Some(parent_context)) = get_container_context(parent_pid) {
                container_context.insert(
                    "parent_container_id".to_string(),
                    parent_context
                        .get("container_id")
                        .cloned()
                        .unwrap_or_else(|| "unknown".to_string()),
                );
                if let Some(parent_pod) = parent_context.get("pod_name") {
                    container_context.insert("parent_pod_name".to_string(), parent_pod.clone());
                }
            }
        }
    }

    if event.event_type == EVENT_TYPE_PTRACE {
        if let Some(target_pid) = event.ptrace_target_pid {
            if let Ok(Some(target_process)) = get_container_context(target_pid) {
                container_context.insert(
                    "target_container_id".to_string(),
                    target_process
                        .get("container_id")
                        .cloned()
                        .unwrap_or_else(|| "unknown".to_string()),
                );
                if let Some(target_pod) = target_process.get("pod_name") {
                    container_context.insert("target_pod_name".to_string(), target_pod.clone());
                }
            }
        }
    }

    Ok(SecurityEvent {
        timestamp: Some(Timestamp {
            seconds: event.timestamp as i64,
            nanos: 0,
        }),
        event_type,
        pid: event.pid as i32,
        ppid: event.parent_pid.unwrap_or(0) as i32,
        command: event.comm.clone(),
        file_path: if event.event_type == EVENT_TYPE_CHMOD {
            event.chmod_path.clone().unwrap_or_default()
        } else {
            event.filename.clone().unwrap_or_default()
        },
        destination_ip: if event.event_type == EVENT_TYPE_CONNECT {
            event.daddr.clone().unwrap_or_default()
        } else {
            String::new()
        },
        destination_port: if event.event_type == EVENT_TYPE_CONNECT {
            event.dport.unwrap_or(0) as i32
        } else {
            0
        },
        source_ip: if event.event_type == EVENT_TYPE_ACCEPT {
            event.daddr.clone().unwrap_or_default()
        } else {
            String::new()
        },
        source_port: if event.event_type == EVENT_TYPE_ACCEPT {
            event.dport.unwrap_or(0) as i32
        } else {
            0
        },
        uid: event.uid.unwrap_or(0) as i32,
        gid: event.gid.unwrap_or(0) as i32,
        ptrace_request: event.ptrace_request.unwrap_or(-1),
        ptrace_target_pid: event.ptrace_target_pid.map(|pid| pid as i32).unwrap_or(-1),
        mode: if event.event_type == EVENT_TYPE_CHMOD {
            event.chmod_mode.unwrap_or(0)
        } else {
            0
        },
        container_context,
    })
}

fn target_context(process_context: Option<HashMap<String, String>>) -> HashMap<String, String> {
    match process_context {
        Some(mut context) => {
            context.insert("attribution_status".to_string(), "resolved".to_string());
            context.insert("target_scope".to_string(), "container".to_string());
            context
                .entry("pod_name".to_string())
                .or_insert_with(|| "unknown".to_string());
            context
                .entry("namespace".to_string())
                .or_insert_with(|| "unknown".to_string());
            context
        }
        None => HashMap::from([
            ("attribution_status".to_string(), "unknown".to_string()),
            ("target_scope".to_string(), "host".to_string()),
            ("container_id".to_string(), "unknown".to_string()),
            ("pod_name".to_string(), "unknown".to_string()),
            ("namespace".to_string(), "unknown".to_string()),
        ]),
    }
}

fn add_monitoring_identity(
    container_context: &mut HashMap<String, String>,
    connection: &ConnectionManager,
) {
    container_context.insert(
        "agent_id".to_string(),
        connection.get_agent_id().to_string(),
    );
    container_context.insert(
        "monitoring_agent".to_string(),
        connection.get_pod_name().to_string(),
    );
    container_context.insert(
        "monitoring_node".to_string(),
        connection.get_node_name().to_string(),
    );
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::target_context;

    #[test]
    fn unresolved_attribution_is_marked_unknown_and_host_scoped() {
        let context = target_context(None);

        assert_eq!(context.get("attribution_status").unwrap(), "unknown");
        assert_eq!(context.get("target_scope").unwrap(), "host");
        assert_eq!(context.get("pod_name").unwrap(), "unknown");
        assert_eq!(context.get("namespace").unwrap(), "unknown");
    }

    #[test]
    fn resolved_attribution_preserves_target_identity() {
        let process_context = HashMap::from([
            ("pod_name".to_string(), "customer-workload".to_string()),
            ("namespace".to_string(), "production".to_string()),
        ]);

        let context = target_context(Some(process_context));

        assert_eq!(context.get("attribution_status").unwrap(), "resolved");
        assert_eq!(context.get("target_scope").unwrap(), "container");
        assert_eq!(context.get("pod_name").unwrap(), "customer-workload");
    }

    #[test]
    fn incomplete_target_identity_does_not_fall_back_to_monitoring_agent() {
        let context = target_context(Some(HashMap::from([(
            "container_id".to_string(),
            "container-123".to_string(),
        )])));

        assert_eq!(context.get("pod_name").unwrap(), "unknown");
        assert_eq!(context.get("namespace").unwrap(), "unknown");
    }
}
