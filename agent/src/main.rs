use std::env;
use std::error::Error;
use std::time::Duration;
use std::sync::{Arc, Mutex as StdMutex};
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use prost_types::Timestamp;
use tonic::Request;
use tonic::transport::Endpoint;
use log::{error, info, debug, warn};
use env_logger::{Builder, Env};
use futures::stream;
use std::io::Write;

mod connection;
use connection::ConnectionManager;

use agent_core::{SyscallMonitor, EventOutput}; 

pub mod telemetry {
    tonic::include_proto!("telemetry");
}

use telemetry::{SecurityEvent, telemetry_service_client::TelemetryServiceClient};

// Event types
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
const EVENT_TYPE_CHMOD: u32 = 15;

// Original buffer sizes and timeouts
const EVENT_CHANNEL_SIZE: usize = 50000;  
const EVENT_BATCH_SIZE: usize = 1000;      
const EVENT_BATCH_TIMEOUT_MS: u64 = 500;  
const BPF_POLL_TIMEOUT_MS: u32 = 500;     
const RECONNECT_DELAY_MS: u64 = 1000;
const EVENT_SEND_TIMEOUT: Duration = Duration::from_millis(500); 
const MAX_RETRIES: usize = 3;             

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
        let endpoint = endpoint.clone();
        info!("Attempting to connect to controller at {}", endpoint);
        
        let uri = format!("http://{}", endpoint);
        match connect_and_run(&uri).await {
            Ok(_) => {
                warn!("Connection closed, attempting to reconnect in {} ms...", RECONNECT_DELAY_MS);
                tokio::time::sleep(Duration::from_millis(RECONNECT_DELAY_MS)).await;
            }
            Err(e) => {
                error!("Connection error: {}", e);
                warn!("Retrying connection in {} ms...", RECONNECT_DELAY_MS);
                tokio::time::sleep(Duration::from_millis(RECONNECT_DELAY_MS)).await;
            }
        }
    }
}

async fn connect_and_run(uri: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    let channel = Endpoint::from_shared(uri.to_string())?
        .tcp_keepalive(Some(Duration::from_secs(30)))
        .tcp_nodelay(true)
        .timeout(Duration::from_secs(10))
        .connect()
        .await?;

    info!("Channel established to controller");
    let client = TelemetryServiceClient::new(channel.clone());
    
    // Create and connect the connection manager
    let mut conn_manager = ConnectionManager::new(
        client.clone(),
        env::var("NODE_NAME").unwrap_or_else(|_| "unknown".to_string()),
        env::var("POD_NAME").unwrap_or_else(|_| "unknown".to_string()),
    );

    match conn_manager.connect().await {
        Ok(true) => {
            info!("Successfully connected to controller");
            
            // Create channels for event communication
            let (event_tx, event_rx) = mpsc::channel(EVENT_CHANNEL_SIZE);
            
            // Start the syscall monitor
            let mut monitor = SyscallMonitor::new()?;
            monitor.attach()?;
            
            // Set up ring buffer with callback
            let tx = event_tx.clone();
            monitor.setup_ring_buffer(move |data| {
                if let Some(event_output) = agent_core::syscalls::parse_bpf_event(data) {
                    let tx = tx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = tx.send(event_output).await {
                            error!("Failed to send event: {}", e);
                        }
                    });
                }
                0 // Continue processing events
            })?;
            
            // Spawn event collection task
            let collection_handle = tokio::spawn(async move {
                loop {
                    if let Err(e) = monitor.poll(BPF_POLL_TIMEOUT_MS) {
                        error!("Event collection error: {}", e);
                        break;
                    }
                }
            });

            // Start heartbeat in separate task
            let mut conn_manager_heartbeat = conn_manager.clone();
            let heartbeat_handle = tokio::spawn(async move {
                loop {
                    match conn_manager_heartbeat.start_heartbeat().await {
                        Ok(_) => (),
                        Err(e) => {
                            error!("Heartbeat error: {}", e);
                            break;
                        }
                    }
                }
            });

            // Start event processing
            let mut batch = Vec::with_capacity(EVENT_BATCH_SIZE);
            let mut stream = ReceiverStream::new(event_rx);

            while let Some(event) = stream.next().await {
                if !conn_manager.is_connected() {
                    error!("Lost connection to controller");
                    break;
                }

                match convert_eventoutput_to_securityevent(&event, &conn_manager) {
                    Ok(security_event) => {
                        batch.push(security_event);
                        
                        if batch.len() >= EVENT_BATCH_SIZE {
                            let events_request = Request::new(stream::iter(batch.drain(..)));
                            
                            // Try to send events with retries
                            for attempt in 1..=MAX_RETRIES {
                                match client.stream_events(events_request.clone()).await {
                                    Ok(_) => {
                                        debug!("Successfully sent events batch");
                                        break;
                                    }
                                    Err(e) => {
                                        error!("Failed to send events batch (attempt {}/{}): {}", attempt, MAX_RETRIES, e);
                                        if attempt == MAX_RETRIES {
                                            return Err(Box::new(e));
                                        }
                                        tokio::time::sleep(Duration::from_millis(RECONNECT_DELAY_MS)).await;
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => error!("Failed to convert event: {}", e),
                }
            }

            // Wait for tasks to complete
            heartbeat_handle.abort();
            collection_handle.abort();
            
            Ok(())
        }
        Ok(false) => {
            error!("Failed to connect to controller");
            Err("Connection failed".into())
        }
        Err(e) => {
            error!("Connection error: {}", e);
            Err(Box::new(e))
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize logging based on DEBUG environment variable
    let env = Env::default()
        .filter_or("DEBUG", "info") // Use "info" level if DEBUG not set
        .write_style_or("LOG_STYLE", "always");

    Builder::from_env(env)
        .format_timestamp_millis()
        .format(|buf, record| {
            use chrono::Local;
            let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
            writeln!(
                buf,
                "[{}] {} - {}",
                timestamp,
                record.level(),
                record.args()
            )
        })
        .init();

    info!("Starting RASP Pod Agent...");

    let config = Arc::new(StdMutex::new(AgentConfig::load()));
    info!("Configuration loaded: {:?}", config.lock().unwrap());
    
    let endpoint = config.lock().unwrap().controller_endpoint.clone();
    info!("Attempting to connect to controller at: {}", endpoint);
    
    // Run the event sender
    if let Err(e) = run_event_sender(endpoint).await {
        error!("Event sender error: {:?}", e);
    }
    
    Ok(())
}

// Helper function to convert EventOutput to SecurityEvent
fn convert_eventoutput_to_securityevent(event: &EventOutput, conn_manager: &ConnectionManager) -> Result<SecurityEvent, Box<dyn Error>> {
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
        EVENT_TYPE_CHMOD => telemetry::EventType::Open as i32, // Map chmod to Open for now
        _ => return Err("Unknown event type".into()),
    };

    let mut container_context = std::collections::HashMap::new();
    container_context.insert("agent_id".to_string(), conn_manager.get_agent_id().to_string());

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
        container_context,
    })
}
