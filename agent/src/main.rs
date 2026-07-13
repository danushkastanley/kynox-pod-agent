use std::env;
use std::error::Error;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_stream::stream;
use env_logger::{Builder, Env};
use log::{debug, error, info, warn};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, Mutex};
use tokio_stream::StreamExt;
use tonic::metadata::MetadataValue;
use tonic::transport::Endpoint;
use tonic::Request;

mod connection;
use connection::ConnectionManager;

use agent_core::SyscallMonitor;

pub mod telemetry {
    tonic::include_proto!("telemetry");
}

use telemetry::telemetry_service_client::TelemetryServiceClient;

type BoxError = Box<dyn Error + Send + Sync + 'static>;

const EVENT_CHANNEL_SIZE: usize = 50000;
const BPF_POLL_TIMEOUT_MS: u32 = 500;
const RECONNECT_DELAY_MS: u64 = 1000;
const MAX_RETRIES: usize = 3;

mod cache;
mod event_conversion;
mod mtls;
mod utils;
use cache::get_cache;
use event_conversion::convert_eventoutput_to_securityevent;
use mtls::{controller_uri, load_client_tls_config, AgentConfig};

async fn run_event_sender(config: AgentConfig) -> Result<(), BoxError> {
    loop {
        let config = config.clone();
        if config.mtls_enabled {
            info!(
                "Attempting mTLS connection to controller at {}",
                config.controller_endpoint
            );
        } else {
            warn!("mTLS is disabled for the gRPC client; use only for local development");
            info!(
                "Attempting plaintext connection to controller at {}",
                config.controller_endpoint
            );
        }

        match connect_and_run(config).await {
            Ok(_) => {
                warn!(
                    "Connection closed, attempting to reconnect in {} ms...",
                    RECONNECT_DELAY_MS
                );
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

async fn connect_and_run(config: AgentConfig) -> Result<(), BoxError> {
    let uri = controller_uri(&config);

    let endpoint = match Endpoint::from_shared(uri.clone()) {
        Ok(endpoint) => endpoint,
        Err(e) => {
            error!("Failed to create endpoint: {}", e);
            return Err(Box::new(e));
        }
    };

    let endpoint = if config.mtls_enabled {
        let tls_config = match load_client_tls_config(&config) {
            Ok(tls_config) => tls_config,
            Err(e) => {
                error!("Failed to load mTLS client configuration: {}", e);
                return Err(e);
            }
        };

        match endpoint.tls_config(tls_config) {
            Ok(endpoint) => endpoint,
            Err(e) => {
                error!("Failed to apply mTLS client configuration: {}", e);
                return Err(Box::new(e));
            }
        }
    } else {
        endpoint
    };

    let channel = match endpoint
        .tcp_keepalive(Some(Duration::from_secs(30)))
        .tcp_nodelay(true)
        .timeout(Duration::from_secs(10))
        .connect()
        .await
    {
        Ok(channel) => channel,
        Err(e) => {
            error!("Failed to connect to endpoint: {}", e);
            return Err(Box::new(e));
        }
    };

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

            // Start the heartbeat task in a separate task
            let mut heartbeat_manager = conn_manager.clone();
            tokio::spawn(async move {
                if let Err(e) = heartbeat_manager.start_heartbeat().await {
                    error!("Heartbeat task failed: {}", e);
                }
            });

            // Start container cache cleanup task (runs every 60 seconds)
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(60));
                loop {
                    interval.tick().await;
                    let cache = get_cache();
                    cache.cleanup_expired();

                    // Log cache stats periodically
                    let stats = cache.stats();
                    debug!(
                        "Container cache stats - size: {}, hits: {}, misses: {}, hit_rate: {:.1}%, evictions: {}",
                        cache.len(),
                        stats.hits,
                        stats.misses,
                        stats.hit_rate() * 100.0,
                        stats.evictions
                    );
                }
            });

            // Start the syscall monitor
            let mut monitor = SyscallMonitor::new()?;
            monitor.attach()?;

            // Set up ring buffer with callback
            let tx = event_tx.clone();
            let dropped_events = Arc::new(AtomicU64::new(0));
            let channel_closed = Arc::new(AtomicBool::new(false));
            monitor.setup_ring_buffer(move |data| {
                if let Some(event_output) = agent_core::syscalls::parse_bpf_event(data) {
                    match tx.try_send(event_output) {
                        Ok(()) => {}
                        Err(TrySendError::Full(_)) => {
                            let dropped = dropped_events.fetch_add(1, Ordering::Relaxed) + 1;
                            if dropped == 1 || dropped.is_multiple_of(1_000) {
                                warn!(
                                    "Event channel full; dropping security event (total dropped: {})",
                                    dropped
                                );
                            }
                        }
                        Err(TrySendError::Closed(_)) => {
                            if !channel_closed.swap(true, Ordering::Relaxed) {
                                error!("Event channel closed; dropping subsequent security events");
                            }
                        }
                    }
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

            // Start event processing
            let mut client = client.clone();
            let conn_manager = Arc::new(Mutex::new(conn_manager));
            let conn_manager_clone = Arc::clone(&conn_manager);
            let (agent_id, session_id) = {
                let connection = conn_manager.lock().await;
                let session_id = connection
                    .get_session_id()
                    .ok_or("No active session for event stream")?
                    .to_string();
                (connection.get_agent_id().to_string(), session_id)
            };

            let events_stream = stream! {
                let mut rx = tokio_stream::wrappers::ReceiverStream::new(event_rx);
                while let Some(event) = rx.next().await {
                    let conn_guard = conn_manager_clone.lock().await;
                    if !conn_guard.is_connected() {
                        error!("Lost connection to controller, attempting reconnect...");
                        drop(conn_guard); // Release lock before reconnect

                        // Try to reconnect
                        let mut retry_count = 0;
                        let mut reconnected = false;
                        while retry_count < MAX_RETRIES {
                            let mut conn_guard = conn_manager_clone.lock().await;
                            match conn_guard.connect().await {
                                Ok(true) => {
                                    info!("Successfully reconnected to controller");
                                    reconnected = true;
                                    break;
                                }
                                _ => {
                                    retry_count += 1;
                                    warn!("Reconnect attempt {} failed, retrying in {} ms...", retry_count, RECONNECT_DELAY_MS);
                                    drop(conn_guard); // Release lock before sleep
                                    tokio::time::sleep(Duration::from_millis(RECONNECT_DELAY_MS)).await;
                                }
                            }
                        }
                        if !reconnected {
                            error!("Failed to reconnect after {} attempts", MAX_RETRIES);
                            break;
                        }
                        continue; // Skip this event and try next one
                    }

                    match convert_eventoutput_to_securityevent(&event, &conn_guard) {
                        Ok(security_event) => {
                            yield security_event;
                        }
                        Err(e) => {
                            error!("Failed to convert event: {}", e);
                        }
                    }
                }
            };

            let stream_request =
                authenticated_stream_request(events_stream, &agent_id, &session_id)?;
            let stream_result = async {
                let mut acknowledgements = client.stream_events(stream_request).await?.into_inner();
                while let Some(acknowledgement) = acknowledgements.message().await? {
                    if acknowledgement.success {
                        debug!("Controller acknowledged security event");
                    } else {
                        warn!(
                            "Controller rejected security event: {}",
                            acknowledgement.message
                        );
                    }
                }

                Err::<(), BoxError>("Event acknowledgement stream closed".into())
            }
            .await;

            collection_handle.abort();
            stream_result
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

fn authenticated_stream_request<T>(
    stream: T,
    agent_id: &str,
    session_id: &str,
) -> Result<Request<T>, BoxError> {
    let mut request = Request::new(stream);
    let agent_id = MetadataValue::try_from(agent_id)?;
    let session_id = MetadataValue::try_from(session_id)?;
    request.metadata_mut().insert("x-agent-id", agent_id);
    request.metadata_mut().insert("x-session-id", session_id);
    Ok(request)
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
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

    let config = Arc::new(Mutex::new(AgentConfig::load()));
    {
        let config = config.lock().await;
        info!(
            "Configuration loaded: controller_endpoint={}, mtls_enabled={}, tls_server_name={}",
            config.controller_endpoint, config.mtls_enabled, config.mtls_server_name
        );
    }

    let config = config.lock().await.clone();
    info!(
        "Attempting to connect to controller at: {}",
        config.controller_endpoint
    );

    // Run the event sender
    if let Err(e) = run_event_sender(config).await {
        error!("Event sender error: {:?}", e);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::authenticated_stream_request;

    #[test]
    fn event_stream_request_includes_agent_session_identity() {
        let request = authenticated_stream_request((), "agent-123", "session-456").unwrap();

        assert_eq!(request.metadata().get("x-agent-id").unwrap(), "agent-123");
        assert_eq!(
            request.metadata().get("x-session-id").unwrap(),
            "session-456"
        );
    }
}
