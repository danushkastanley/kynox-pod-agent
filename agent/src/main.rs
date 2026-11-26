use std::env;
use std::error::Error;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use agent_core::{EventOutput, SyscallMonitor};
use env_logger::{Builder, Env};
use log::{debug, error, info, warn};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, Mutex};
use tokio_stream::wrappers::ReceiverStream;
use tonic::metadata::MetadataValue;
use tonic::transport::{Channel, Endpoint};
use tonic::Request;
use uuid::Uuid;

mod cache;
mod connection;
mod event_conversion;
mod mtls;
mod utils;

use cache::get_cache;
use connection::ConnectionManager;
use event_conversion::convert_eventoutput_to_securityevent;
use mtls::{controller_uri, load_client_tls_config, AgentConfig};

// Generated tonic client code returns tonic::Status (large) in Result; not ours to reshape.
#[allow(clippy::result_large_err)]
pub mod telemetry {
    tonic::include_proto!("telemetry");
}

use telemetry::telemetry_service_client::TelemetryServiceClient;
use telemetry::SecurityEvent;

type BoxError = Box<dyn Error + Send + Sync + 'static>;
/// Events collected from the kernel. Shared across connections so that events buffered
/// while the controller is unreachable are sent after the agent reconnects.
type EventReceiver = Arc<Mutex<mpsc::Receiver<EventOutput>>>;

const EVENT_CHANNEL_SIZE: usize = 50000;
const STREAM_BUFFER_SIZE: usize = 1024;
const BPF_POLL_TIMEOUT_MS: u32 = 500;
const RECONNECT_DELAY: Duration = Duration::from_secs(1);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const CACHE_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

/// Identity that must survive reconnects so the controller resumes the same registration.
struct AgentSession {
    agent_id: String,
    session_id: Option<String>,
}

/// Loads and attaches the eBPF programs once for the life of the process and polls the
/// ring buffer on a dedicated thread (polling blocks, so it must not run on the async runtime).
fn start_monitor(tx: mpsc::Sender<EventOutput>) -> Result<(), BoxError> {
    let mut monitor = SyscallMonitor::new()?;
    monitor.attach()?;

    let dropped_events = AtomicU64::new(0);
    let channel_closed = AtomicBool::new(false);
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

    std::thread::Builder::new()
        .name("bpf-poll".to_string())
        .spawn(move || loop {
            if let Err(e) = monitor.poll(BPF_POLL_TIMEOUT_MS) {
                // Without polling the agent silently stops monitoring. Exit so the
                // orchestrator restarts it and the failure is visible.
                error!("Event collection failed; exiting: {}", e);
                std::process::exit(1);
            }
        })?;

    Ok(())
}

fn spawn_cache_cleanup() {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(CACHE_CLEANUP_INTERVAL);
        loop {
            interval.tick().await;
            let cache = get_cache();
            cache.cleanup_expired();

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
}

async fn run_event_sender(config: AgentConfig, events: EventReceiver) {
    let mut session = AgentSession {
        agent_id: Uuid::new_v4().to_string(),
        session_id: None,
    };

    loop {
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

        if let Err(e) = connect_and_run(&config, &mut session, Arc::clone(&events)).await {
            error!("Connection error: {}", e);
        }
        warn!("Reconnecting to controller in {:?}...", RECONNECT_DELAY);
        tokio::time::sleep(RECONNECT_DELAY).await;
    }
}

async fn connect_channel(config: &AgentConfig) -> Result<Channel, BoxError> {
    let mut endpoint = Endpoint::from_shared(controller_uri(config))?;
    if config.mtls_enabled {
        endpoint = endpoint.tls_config(load_client_tls_config(config)?)?;
    }

    // connect_timeout bounds connection setup only. A request-level timeout would also
    // cancel the long-lived event stream.
    let channel = endpoint
        .connect_timeout(CONNECT_TIMEOUT)
        .tcp_keepalive(Some(Duration::from_secs(30)))
        .tcp_nodelay(true)
        .connect()
        .await?;
    Ok(channel)
}

/// Runs one controller connection until the event stream or the heartbeat fails.
async fn connect_and_run(
    config: &AgentConfig,
    session: &mut AgentSession,
    events: EventReceiver,
) -> Result<(), BoxError> {
    let channel = connect_channel(config).await?;
    info!("Channel established to controller");
    let mut client = TelemetryServiceClient::new(channel);

    let mut connection = ConnectionManager::new(
        client.clone(),
        session.agent_id.clone(),
        env::var("NODE_NAME").unwrap_or_else(|_| "unknown".to_string()),
        env::var("POD_NAME").unwrap_or_else(|_| "unknown".to_string()),
        session.session_id.clone(),
    );
    if !connection.connect().await? {
        return Err("Connection rejected by controller".into());
    }
    let session_id = connection
        .get_session_id()
        .ok_or("No active session for event stream")?
        .to_string();
    session.session_id = Some(session_id.clone());

    let mut heartbeat_connection = connection.clone();
    let mut heartbeat = tokio::spawn(async move { heartbeat_connection.start_heartbeat().await });

    // The forwarder is the only reader of the shared receiver while this connection is
    // live. Aborting it releases the receiver deterministically, even if the transport
    // keeps the request stream alive after the connection has failed.
    let (stream_tx, stream_rx) = mpsc::channel(STREAM_BUFFER_SIZE);
    let forwarder = tokio::spawn(forward_to_stream(events, connection, stream_tx));

    let request = authenticated_stream_request(
        ReceiverStream::new(stream_rx),
        &session.agent_id,
        &session_id,
    )?;
    let result = tokio::select! {
        result = stream_events(&mut client, request) => result,
        heartbeat_result = &mut heartbeat => match heartbeat_result {
            Ok(Ok(())) => Err("Heartbeat stopped".into()),
            Ok(Err(e)) => Err(Box::new(e) as BoxError),
            Err(e) => Err(Box::new(e) as BoxError),
        },
    };

    heartbeat.abort();
    forwarder.abort();
    result
}

async fn forward_to_stream(
    events: EventReceiver,
    connection: ConnectionManager,
    stream_tx: mpsc::Sender<SecurityEvent>,
) {
    let mut events = events.lock_owned().await;
    while let Some(event) = events.recv().await {
        match convert_eventoutput_to_securityevent(&event, &connection) {
            Ok(security_event) => {
                if stream_tx.send(security_event).await.is_err() {
                    break; // Stream closed; the connection is ending.
                }
            }
            Err(e) => error!("Failed to convert event: {}", e),
        }
    }
}

async fn stream_events(
    client: &mut TelemetryServiceClient<Channel>,
    request: Request<ReceiverStream<SecurityEvent>>,
) -> Result<(), BoxError> {
    let mut acknowledgements = client.stream_events(request).await?.into_inner();
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

    Err("Event acknowledgement stream closed".into())
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

    let config = AgentConfig::load();
    info!(
        "Configuration loaded: controller_endpoint={}, mtls_enabled={}, tls_server_name={}",
        config.controller_endpoint, config.mtls_enabled, config.mtls_server_name
    );

    // Fail fast: an agent that cannot load or attach its eBPF programs must not look healthy.
    let (event_tx, event_rx) = mpsc::channel(EVENT_CHANNEL_SIZE);
    start_monitor(event_tx)?;
    spawn_cache_cleanup();

    run_event_sender(config, Arc::new(Mutex::new(event_rx))).await;
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
