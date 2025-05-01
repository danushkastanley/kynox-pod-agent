use std::env;
use std::error::Error;
use std::collections::HashMap;
use std::time::Duration;
use std::sync::Arc;
use std::sync::Mutex;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use prost_types::Timestamp;
use tonic::{transport::Channel, Request};
use log::{debug, info, warn, error};
use tokio::task;

use agent_core::{SyscallMonitor, parse_bpf_event, EventOutput}; 
use agent_core::constants::*; 

pub mod telemetry {
    tonic::include_proto!("telemetry");
}

use telemetry::{SecurityEvent, telemetry_service_client::TelemetryServiceClient};

const EVENT_CHANNEL_SIZE: usize = 100;
const BPF_POLL_TIMEOUT_MS: u32 = 100; 

#[derive(Debug, Clone)]
struct AgentConfig {
    controller_endpoint: String,
}

impl AgentConfig {
    fn load() -> Self {
        let controller_endpoint = env::var("CONTROLLER_ENDPOINT")
            .unwrap_or_else(|_| "http://[::1]:50051".to_string());
        AgentConfig {
            controller_endpoint,
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    log::info!("Starting RASP Pod Agent...");

    let config = Arc::new(Mutex::new(AgentConfig::load()));
    log::info!("Configuration loaded: {:?}", config.lock().unwrap());

    let endpoint = config.lock().unwrap().controller_endpoint.clone();
    log::info!("Attempting to connect to controller at: {}", endpoint);
    let channel = loop {
        match Channel::from_shared(endpoint.clone())?.connect().await {
            Ok(channel) => {
                log::info!("Successfully connected to controller.");
                break channel;
            }
            Err(e) => {
                log::error!("Failed to connect: {}. Retrying in 5s...", e);
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    };
    let client = TelemetryServiceClient::new(channel);
    log::info!("Telemetry client created.");

    let (event_tx, event_rx) = mpsc::channel::<SecurityEvent>(EVENT_CHANNEL_SIZE);
    let mut client_clone = client.clone();
    let grpc_sender_handle = tokio::spawn(async move {
        log::info!("Starting gRPC event sender task...");
        let event_stream = ReceiverStream::new(event_rx);
        match client_clone.send_events(Request::new(event_stream)).await {
            Ok(response) => {
                log::info!("gRPC server responded: {:?}", response.into_inner());
            }
            Err(e) => {
                log::error!("SendEvents stream failed: {}", e);
            }
        }
        log::info!("gRPC event sender task finished.");
    });
    log::info!("Event sender task spawned.");

    log::info!("Initializing BPF Syscall Monitor...");
    let mut monitor = SyscallMonitor::new()?;
    monitor.attach()?;
    log::info!("BPF programs attached.");

    let event_tx_clone = event_tx.clone();

    let bpf_event_callback = move |data: &[u8]| {
        match parse_bpf_event(data) {
            Some(parsed_event) => {
                match convert_eventoutput_to_securityevent(&parsed_event) {
                    Ok(security_event) => {
                        match event_tx_clone.try_send(security_event) {
                            Ok(_) => { /* log::debug!("Event sent to channel"); */ }
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                log::warn!("Event channel full, dropping event: PID {}", parsed_event.pid);
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                log::error!("Event channel closed, cannot send event.");
                                return 1; 
                            }
                        }
                    }
                    Err(e) => {
                         log::error!("Failed to convert BPF event (PID {}): {}", parsed_event.pid, e);
                    }
                }
            }
            None => {
                log::warn!("Failed to parse BPF event from raw data ({} bytes)", data.len());
            }
        }
        0 
    };

    monitor.setup_ring_buffer(bpf_event_callback)?;
    log::info!("Ring buffer setup complete. Starting event poll loop...");

    let monitor_arc = Arc::new(Mutex::new(monitor));
    let monitor_clone = Arc::clone(&monitor_arc);
    let polling_handle = task::spawn_blocking(move || {
         log::info!("BPF polling task started.");
         loop {
            match monitor_clone.lock().unwrap().poll(BPF_POLL_TIMEOUT_MS) {
                Ok(_) => { /* Successful poll cycle */ }
                Err(e) => {
                    log::error!("BPF polling error: {}. Exiting poll loop.", e);
                    break; 
                }
            }
        }
        log::warn!("BPF polling task finished.");
    });

    let _ = tokio::join!(
        polling_handle,
        grpc_sender_handle
    ) as (Result<(), task::JoinError>, Result<(), task::JoinError>);

    log::warn!("Agent shutting down.");
    Ok(())
}

fn convert_eventoutput_to_securityevent(event: &EventOutput) -> Result<telemetry::SecurityEvent, Box<dyn std::error::Error>> {
    log::debug!("Converting EventOutput (PID: {}) to SecurityEvent", event.pid);

    let event_type_proto = match event.event_type {
        EVENT_TYPE_EXEC => telemetry::EventType::Exec as i32,
        EVENT_TYPE_OPEN => telemetry::EventType::Open as i32,
        EVENT_TYPE_CONNECT => telemetry::EventType::Connect as i32,
        EVENT_TYPE_ACCEPT => telemetry::EventType::Accept as i32,
        EVENT_TYPE_SETUID => telemetry::EventType::Setuid as i32,
        EVENT_TYPE_CAPSET => telemetry::EventType::Capset as i32,
        EVENT_TYPE_FORK => telemetry::EventType::Fork as i32,
        EVENT_TYPE_PTRACE => telemetry::EventType::Ptrace as i32,
        EVENT_TYPE_SETGID => telemetry::EventType::Setgid as i32,
        EVENT_TYPE_MOUNT => telemetry::EventType::Mount as i32,
        EVENT_TYPE_UMOUNT => telemetry::EventType::Umount as i32,
        EVENT_TYPE_BPF_PROG => telemetry::EventType::BpfProg as i32,
        EVENT_TYPE_SECCOMP => telemetry::EventType::Seccomp as i32,
        EVENT_TYPE_SOCKET => telemetry::EventType::Socket as i32,
        EVENT_TYPE_BIND => telemetry::EventType::Bind as i32,
        _ => {
            warn!("Received unknown event type from BPF: {}", event.event_type);
            0 // Default to unspecified (0)
        }
    };

    let timestamp = Some(Timestamp {
        seconds: event.timestamp as i64,
        nanos: 0,
    });

    Ok(telemetry::SecurityEvent {
        event_type: event_type_proto,
        pid: event.pid as i32,
        ppid: event.parent_pid.map(|p| p as i32).unwrap_or(-1),
        command: event.comm.clone(),
        file_path: event.filename.as_ref().map_or_else(String::new, |s| s.clone()),
        timestamp,
        destination_ip: if event.event_type == EVENT_TYPE_CONNECT {
            event.daddr.as_ref().map_or_else(String::new, |s| s.clone())
        } else {
            String::new()
        },
        destination_port: if event.event_type == EVENT_TYPE_CONNECT {
            event.dport.map(|p| p as i32).unwrap_or(0)
        } else {
            0
        },
        source_ip: if event.event_type == EVENT_TYPE_ACCEPT {
            event.daddr.as_ref().map_or_else(String::new, |s| s.clone())
        } else {
            String::new()
        },
        source_port: if event.event_type == EVENT_TYPE_ACCEPT {
            event.dport.map(|p| p as i32).unwrap_or(0)
        } else {
            0
        },
        uid: event.uid.map(|u| u as i32).unwrap_or(-1),
        gid: event.gid.map(|g| g as i32).unwrap_or(-1),
        ptrace_request: event.ptrace_request.map(|r| r as i64).unwrap_or(-1),
        ptrace_target_pid: event.ptrace_target_pid.map(|p| p as i32).unwrap_or(-1),
        container_context: HashMap::new(),
    })
}
