use std::env;
use std::error::Error;
use std::time::Duration;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use prost_types::Timestamp;
use tonic::{transport::Channel, Request};
use log::{error, info, debug};
use futures::stream;

mod connection;
use connection::ConnectionManager;

use agent_core::{SyscallMonitor, parse_bpf_event, EventOutput}; 

pub mod telemetry {
    tonic::include_proto!("telemetry");
}

use telemetry::{SecurityEvent, telemetry_service_client::TelemetryServiceClient};

// Increased buffer sizes and timeouts
const EVENT_CHANNEL_SIZE: usize = 50000;
const EVENT_BATCH_SIZE: usize = 500;
const BPF_POLL_TIMEOUT_MS: u32 = 100;
const RECONNECT_DELAY_MS: u64 = 5000;
const EVENT_SEND_TIMEOUT: Duration = Duration::from_millis(500);

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
        Self {
            controller_endpoint: env::var("CONTROLLER_ENDPOINT")
                .unwrap_or_else(|_| "rasp-controller.default.svc:50051".to_string()),
        }
    }
}

async fn run_event_sender(endpoint: String) -> Result<(), Box<dyn Error + Send + Sync>> {
    loop {
        let endpoint = format!("http://{}", endpoint);
        
        match Channel::from_shared(endpoint.clone())?.connect().await {
            Ok(channel) => {
                info!("Channel established to controller");
                let mut client = TelemetryServiceClient::new(channel.clone());
                
                // Create and connect the connection manager
                let mut conn_manager = ConnectionManager::new(
                    client.clone(),
                    env::var("NODE_NAME").unwrap_or_else(|_| "unknown".to_string()),
                    env::var("POD_NAME").unwrap_or_else(|_| "unknown".to_string()),
                );

                match conn_manager.connect().await {
                    Ok(true) => {
                        info!("Successfully connected to controller");
                        
                        // Start heartbeat in separate task
                        let mut conn_manager_heartbeat = conn_manager.clone();
                        tokio::spawn(async move {
                            if let Err(e) = conn_manager_heartbeat.start_heartbeat().await {
                                error!("Heartbeat error: {}", e);
                            }
                        });

                        // Only start collecting events if we're connected
                        if conn_manager.is_connected() {
                            let (tx, mut rx) = mpsc::channel::<SecurityEvent>(EVENT_CHANNEL_SIZE);
                            let tx = Arc::new(Mutex::new(tx));
                            let tx_clone = tx.clone();
                            
                            let _bpf_handle = tokio::spawn(async move {
                                let mut monitor = SyscallMonitor::new().expect("Failed to create syscall monitor");
                                monitor.attach().expect("Failed to attach BPF programs");
                                info!("BPF programs attached successfully");

                                let tx = tx_clone.clone();
                                let _callback = move |data: &[u8]| {
                                    if let Some(event) = parse_bpf_event(data) {
                                        if let Ok(security_event) = convert_eventoutput_to_securityevent(&event) {
                                            let tx = tx.clone();
                                            tokio::spawn(async move {
                                                if let Err(e) = tx.lock().await.send(security_event).await {
                                                    error!("Failed to send event: {}", e);
                                                }
                                            });
                                        }
                                    }
                                };

                                loop {
                                    if let Err(e) = monitor.poll(BPF_POLL_TIMEOUT_MS) {
                                        error!("Error polling events: {:?}", e);
                                        tokio::time::sleep(Duration::from_millis(1000)).await;
                                    }
                                }
                            });

                            // Create a stream from the receiver
                            let mut stream = ReceiverStream::new(rx);
                            let mut events = Vec::with_capacity(EVENT_BATCH_SIZE);

                            while let Some(event) = stream.next().await {
                                events.push(event);
                                if events.len() >= EVENT_BATCH_SIZE {
                                    let batch = std::mem::take(&mut events);
                                    let stream = stream::iter(batch);
                                    if let Err(e) = client.stream_events(Request::new(stream)).await {
                                        error!("Failed to send event batch: {}", e);
                                    }
                                }
                            }

                            // Send any remaining events
                            if !events.is_empty() {
                                let stream = stream::iter(events);
                                if let Err(e) = client.stream_events(Request::new(stream)).await {
                                    error!("Failed to send remaining events: {}", e);
                                }
                            }
                        }
                    }
                    Ok(false) => {
                        error!("Connection rejected by controller");
                    }
                    Err(e) => {
                        error!("Failed to establish connection: {}", e);
                    }
                }
            }
            Err(e) => {
                error!("Channel connection failed: {:?}", e);
                error!("Connection details: Endpoint={}, Error={:#?}", endpoint, e);
                
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
        
        info!("Waiting before reconnection attempt...");
        tokio::time::sleep(Duration::from_millis(RECONNECT_DELAY_MS)).await;
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    info!("Starting RASP Pod Agent...");

    let config = Arc::new(Mutex::new(AgentConfig::load()));
    info!("Configuration loaded: {:?}", config.lock().await);
    
    let endpoint = config.lock().await.controller_endpoint.clone();
    info!("Attempting to connect to controller at: {}", endpoint);
    
    // Run the event sender
    if let Err(e) = run_event_sender(endpoint).await {
        error!("Event sender error: {:?}", e);
    }
    
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
