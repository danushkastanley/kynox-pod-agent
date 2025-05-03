use std::env;
use std::error::Error;
use std::time::{Duration, Instant};
use std::sync::{Arc, Mutex as StdMutex};
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use prost_types::Timestamp;
use tonic::{transport::Channel, Request, Code};
use tonic::transport::Endpoint;
use log::{error, info, debug, warn};
use env_logger::{Builder, Env};
use futures::stream;
use std::io::Write;

mod connection;
use connection::ConnectionManager;

use agent_core::{SyscallMonitor, parse_bpf_event, EventOutput}; 

pub mod telemetry {
    tonic::include_proto!("telemetry");
}

use telemetry::{SecurityEvent, telemetry_service_client::TelemetryServiceClient};

// Increased buffer sizes and timeouts
const EVENT_CHANNEL_SIZE: usize = 100000;  // Doubled buffer size
const EVENT_BATCH_SIZE: usize = 2000;      // Doubled batch size
const EVENT_BATCH_TIMEOUT_MS: u64 = 1000;  // Send batch after 1 second
const BPF_POLL_TIMEOUT_MS: u32 = 1000;     // Poll every second
const RECONNECT_DELAY_MS: u64 = 5000;
const EVENT_SEND_TIMEOUT: Duration = Duration::from_millis(1000); // Increased timeout
const MAX_RETRIES: usize = 3;              // Max retries for sending events

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
    let mut reconnect_delay = RECONNECT_DELAY_MS;
    loop {
        let endpoint = endpoint.clone();
        
        let uri = format!("http://{}", endpoint);
        info!("Attempting to connect to {}", uri);
        
        let channel = Endpoint::from_shared(uri)?
            .tcp_keepalive(Some(Duration::from_secs(30)))
            .tcp_nodelay(true)
            .timeout(Duration::from_secs(10))
            .connect()
            .await;

        match channel {
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
                        let heartbeat_handle = tokio::spawn(async move {
                            loop {
                                match conn_manager_heartbeat.start_heartbeat().await {
                                    Ok(_) => (),
                                    Err(e) => {
                                        error!("Heartbeat error: {}", e);
                                        // Break the loop on error to trigger reconnection
                                        break;
                                    }
                                }
                            }
                        });

                        // Wait for a successful heartbeat before starting event collection
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        
                        // Only start collecting events if we're still connected
                        if conn_manager.is_connected() {
                            // Start event collection
                            let (tx, rx) = mpsc::channel::<SecurityEvent>(EVENT_CHANNEL_SIZE);
                            let monitor = Arc::new(StdMutex::new(SyscallMonitor::new()?));
                            
                            // Event collection task
                            let monitor_clone = monitor.clone();
                            let tx_clone = tx.clone();
                            let conn_manager_clone = conn_manager.clone();
                            
                            tokio::spawn(async move {
                                let mut events = Vec::with_capacity(EVENT_BATCH_SIZE);
                                let mut last_send = Instant::now();
                                let mut consecutive_errors = 0;
                                
                                loop {
                                    // Check channel capacity
                                    if tx_clone.capacity() == 0 {
                                        warn!("Event channel at capacity, applying backpressure...");
                                        tokio::time::sleep(Duration::from_millis(100)).await;
                                        continue;
                                    }

                                    // Poll for events
                                    if let Ok(event_output) = monitor_clone.lock().unwrap().poll_events(BPF_POLL_TIMEOUT_MS) {
                                        match convert_eventoutput_to_securityevent(&event_output, &conn_manager_clone) {
                                            Ok(event) => {
                                                // Try to send with timeout
                                                match tokio::time::timeout(EVENT_SEND_TIMEOUT, tx_clone.send(event)).await {
                                                    Ok(Ok(_)) => {
                                                        // Event sent successfully
                                                        consecutive_errors = 0;
                                                    }
                                                    Ok(Err(e)) => {
                                                        error!("Failed to send event to channel: {}", e);
                                                        consecutive_errors += 1;
                                                    }
                                                    Err(_) => {
                                                        warn!("Event send timed out, applying backpressure");
                                                        consecutive_errors += 1;
                                                    }
                                                }

                                                // If too many consecutive errors, slow down
                                                if consecutive_errors > MAX_RETRIES {
                                                    warn!("Too many consecutive errors, slowing down event collection");
                                                    tokio::time::sleep(Duration::from_secs(1)).await;
                                                    consecutive_errors = 0;
                                                }
                                            }
                                            Err(e) => error!("Failed to convert event: {}", e),
                                        }
                                    }
                                }
                            });

                            // Event sending task
                            let mut stream = ReceiverStream::new(rx);
                            
                            while let Some(event) = stream.next().await {
                                let mut events = vec![event];
                                
                                // Collect more events if available
                                while events.len() < EVENT_BATCH_SIZE {
                                    match stream.next().now_or_never() {
                                        Some(Some(event)) => events.push(event),
                                        _ => break,
                                    }
                                }

                                // Send batch with retries
                                let mut retry_count = 0;
                                while retry_count < MAX_RETRIES {
                                    let stream = stream::iter(events.clone());
                                    match client.stream_events(Request::new(stream)).await {
                                        Ok(_) => {
                                            debug!("Successfully sent batch of {} events", events.len());
                                            break;
                                        }
                                        Err(e) => {
                                            error!("Failed to send events batch (attempt {}/{}): {}", 
                                                retry_count + 1, MAX_RETRIES, e);
                                            retry_count += 1;
                                            if retry_count < MAX_RETRIES {
                                                tokio::time::sleep(Duration::from_millis(100 * retry_count as u64)).await;
                                            }
                                        }
                                    }
                                }
                            }

                            // Clean up handles
                            heartbeat_handle.abort();
                        }
                    }
                    Ok(false) => {
                        error!("Failed to connect to controller - retrying in {} ms", reconnect_delay);
                    }
                    Err(e) => {
                        error!("Connection error: {} - retrying in {} ms", e, reconnect_delay);
                    }
                }
            }
            Err(e) => {
                error!("Channel error: {} - retrying in {} ms", e, reconnect_delay);
            }
        }

        tokio::time::sleep(Duration::from_millis(reconnect_delay)).await;
        // Increase reconnect delay up to 30 seconds
        reconnect_delay = std::cmp::min(reconnect_delay * 2, 30000);
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
        0 => telemetry::EventType::Exec as i32,
        1 => telemetry::EventType::Open as i32,
        2 => telemetry::EventType::Connect as i32,
        3 => telemetry::EventType::Fork as i32,
        4 => telemetry::EventType::Ptrace as i32,
        5 => telemetry::EventType::Setuid as i32,
        6 => telemetry::EventType::Setgid as i32,
        7 => telemetry::EventType::Mount as i32,
        8 => telemetry::EventType::Umount as i32,
        9 => telemetry::EventType::Capset as i32,
        10 => telemetry::EventType::BpfProg as i32,
        11 => telemetry::EventType::Seccomp as i32,
        12 => telemetry::EventType::Socket as i32,
        13 => telemetry::EventType::Bind as i32,
        14 => telemetry::EventType::Accept as i32,
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
        destination_ip: if event.event_type == 2 {
            event.daddr.as_ref().map_or_else(String::new, |s| s.clone())
        } else {
            String::new()
        },
        destination_port: if event.event_type == 2 {
            event.dport.unwrap_or(0) as i32
        } else {
            0
        },
        source_ip: if event.event_type == 14 {
            event.daddr.as_ref().map_or_else(String::new, |s| s.clone())
        } else {
            String::new()
        },
        source_port: if event.event_type == 14 {
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
