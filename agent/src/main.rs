use std::env;
use std::error::Error;
use std::collections::HashMap;
use std::time::Duration;
use std::sync::Arc;
use std::sync::Mutex;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use prost_types::Timestamp;
use tonic::{transport::Channel, Request, Code};
use log::{warn, error, info, debug};
use tokio::task;

use agent_core::{SyscallMonitor, parse_bpf_event, EventOutput}; 
use agent_core::constants::*; 

pub mod telemetry {
    tonic::include_proto!("telemetry");
}

use telemetry::{SecurityEvent, telemetry_service_client::TelemetryServiceClient};

const EVENT_CHANNEL_SIZE: usize = 1000; // Increased buffer size
const BPF_POLL_TIMEOUT_MS: u32 = 100;
const RECONNECT_DELAY_MS: u64 = 5000;

// Event types from agent-core
const EVENT_TYPE_EXEC: u32 = 0;
const EVENT_TYPE_OPEN: u32 = 1;
const EVENT_TYPE_CONNECT: u32 = 2;
const EVENT_TYPE_FORK: u32 = 3;
const EVENT_TYPE_PTRACE: u32 = 4;
const EVENT_TYPE_SETUID: u32 = 5;
const EVENT_TYPE_SETGID: u32 = 6;
const EVENT_TYPE_MOUNT: u32 = 7;
const EVENT_TYPE_UMOUNT: u32 = 8;
const EVENT_TYPE_CAPSET: u32 = 9;
const EVENT_TYPE_BPF_PROG: u32 = 10;
const EVENT_TYPE_SECCOMP: u32 = 11;
const EVENT_TYPE_SOCKET: u32 = 12;
const EVENT_TYPE_BIND: u32 = 13;
const EVENT_TYPE_ACCEPT: u32 = 14;

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

async fn run_event_sender(
    mut client: TelemetryServiceClient<Channel>,
    rx: mpsc::Receiver<SecurityEvent>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    info!("Starting event sender task");
    
    let event_stream = ReceiverStream::new(rx);
    match client.send_events(Request::new(event_stream)).await {
        Ok(response) => {
            info!("Stream completed successfully: {:?}", response.into_inner());
            Ok(())
        }
        Err(status) => {
            error!("Stream error: {:?}", status);
            if status.code() == Code::Unavailable {
                // Server is unavailable - signal for retry
                Err("Server unavailable".into())
            } else {
                Err(Box::new(status))
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    info!("Starting RASP Pod Agent...");

    let config = Arc::new(Mutex::new(AgentConfig::load()));
    info!("Configuration loaded: {:?}", config.lock().unwrap());

    let endpoint = config.lock().unwrap().controller_endpoint.clone();
    info!("Attempting to connect to controller at: {}", endpoint);

    // Create channel for events with larger buffer
    let (event_tx, _event_rx) = mpsc::channel::<SecurityEvent>(EVENT_CHANNEL_SIZE);
    let event_tx = Arc::new(tokio::sync::Mutex::new(event_tx));

    // Start gRPC sender task
    let endpoint_clone = endpoint.clone();
    let grpc_sender_handle = tokio::spawn(async move {
        loop {
            // Create a new channel for each connection attempt
            let (_tx, rx) = mpsc::channel::<SecurityEvent>(EVENT_CHANNEL_SIZE);
            
            match Channel::from_shared(endpoint_clone.clone()) {
                Ok(channel) => {
                    match channel.connect().await {
                        Ok(channel) => {
                            info!("Connected to controller");
                            let client = TelemetryServiceClient::new(channel);
                            
                            if let Err(e) = run_event_sender(client, rx).await {
                                error!("Event sender error: {:?}", e);
                            }
                        }
                        Err(e) => {
                            error!("Connection failed: {:?}", e);
                            error!("Connection details: Endpoint={}, Error={:#?}", endpoint_clone, e);
                            
                            // Try DNS resolution
                            if let Ok(addrs) = tokio::net::lookup_host("rasp-controller.default.svc:50051").await {
                                info!("DNS lookup results for controller:");
                                for addr in addrs {
                                    info!("  Found address: {}", addr);
                                }
                            } else {
                                error!("Failed to resolve controller DNS name");
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Invalid URI: {:?}", e);
                }
            }
            
            info!("Waiting before reconnection attempt...");
            tokio::time::sleep(Duration::from_millis(RECONNECT_DELAY_MS)).await;
        }
    });

    info!("Initializing BPF Syscall Monitor...");
    let mut monitor = SyscallMonitor::new()?;
    monitor.attach()?;
    info!("BPF programs attached.");

    let event_tx_clone = event_tx.clone();
    let bpf_event_callback = move |data: &[u8]| {
        match parse_bpf_event(data) {
            Some(parsed_event) => {
                match convert_eventoutput_to_securityevent(&parsed_event) {
                    Ok(security_event) => {
                        let event_tx = event_tx_clone.clone();
                        tokio::spawn(async move {
                            let tx = event_tx.lock().await;
                            match tx.try_send(security_event) {
                                Ok(_) => debug!("Event sent to channel"),
                                Err(mpsc::error::TrySendError::Full(_)) => {
                                    warn!("Event channel full, dropping event: PID {}", parsed_event.pid);
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => {
                                    error!("Event channel closed - this should not happen");
                                }
                            }
                        });
                    }
                    Err(e) => {
                        error!("Failed to convert BPF event (PID {}): {}", parsed_event.pid, e);
                    }
                }
            }
            None => {
                warn!("Failed to parse BPF event from raw data ({} bytes)", data.len());
            }
        }
        0 
    };

    monitor.setup_ring_buffer(bpf_event_callback)?;
    info!("Ring buffer setup complete. Starting event poll loop...");

    let monitor_arc = Arc::new(monitor);
    let monitor_clone = Arc::clone(&monitor_arc);
    let polling_handle = task::spawn_blocking(move || {
        info!("BPF polling task started.");
        loop {
            match monitor_clone.poll(BPF_POLL_TIMEOUT_MS) {
                Ok(_) => { /* Successful poll cycle */ }
                Err(e) => {
                    error!("BPF polling error: {}. Exiting poll loop.", e);
                    break;
                }
            }
        }
        warn!("BPF polling task finished.");
    });

    let _ = tokio::join!(
        polling_handle,
        grpc_sender_handle
    ) as (Result<(), task::JoinError>, Result<(), task::JoinError>);

    warn!("Agent shutting down.");
    Ok(())
}

// Helper function to convert EventOutput to SecurityEvent
fn convert_eventoutput_to_securityevent(event: &EventOutput) -> Result<SecurityEvent, Box<dyn Error>> {
    debug!("Converting EventOutput (PID: {}) to SecurityEvent", event.pid);

    let event_type_proto = match event.event_type {
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
        _ => return Err("Unknown event type".into()),
    };

    Ok(SecurityEvent {
        timestamp: Some(Timestamp {
            seconds: event.timestamp as i64,
            nanos: 0,
        }),
        event_type: event_type_proto,
        pid: event.pid as i32,
        ppid: event.parent_pid.unwrap_or(0) as i32,
        command: event.comm.clone(),
        file_path: event.filename.as_ref().map_or_else(String::new, |s| s.clone()),
        destination_ip: if event.event_type == EVENT_TYPE_CONNECT {
            event.daddr.as_ref().map_or_else(String::new, |s| s.clone())
        } else {
            String::new()
        },
        destination_port: if event.event_type == EVENT_TYPE_CONNECT {
            event.dport.unwrap_or(0) as i32
        } else {
            0
        },
        source_ip: if event.event_type == EVENT_TYPE_ACCEPT {
            event.daddr.as_ref().map_or_else(String::new, |s| s.clone())
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
        ptrace_request: event.ptrace_request.map(|r| r as i64).unwrap_or(-1),
        ptrace_target_pid: event.ptrace_target_pid.map(|p| p as i32).unwrap_or(-1),
        container_context: Default::default(),
    })
}
