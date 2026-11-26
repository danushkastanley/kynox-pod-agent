use std::time::Duration;

use log::{debug, error, info, warn};
use tokio::time;
use tonic::metadata::MetadataValue;
use tonic::transport::Channel;
use tonic::{Request, Status};

use crate::telemetry::{
    telemetry_service_client::TelemetryServiceClient, ConnectRequest, Heartbeat,
};

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(300); // 5 minutes
const INITIAL_RECONNECT_DELAY: Duration = Duration::from_secs(1);
/// Deadline for unary RPCs. The event stream is long-lived and has no deadline.
const RPC_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub enum ConnectionError {
    Grpc(Box<Status>),
    Metadata(String),
    Session(String),
}

impl std::fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Grpc(s) => write!(f, "gRPC error: {}", s),
            Self::Metadata(msg) => write!(f, "Metadata error: {}", msg),
            Self::Session(msg) => write!(f, "Session error: {}", msg),
        }
    }
}

impl std::error::Error for ConnectionError {}

#[derive(Clone)]
pub struct ConnectionManager {
    client: TelemetryServiceClient<Channel>,
    agent_id: String,
    node_name: String,
    pod_name: String,
    session_id: Option<String>,
}

impl ConnectionManager {
    /// `agent_id` must stay the same for the life of the process, and `previous_session_id`
    /// is the last session the controller issued to it, so a reconnect resumes the same
    /// registration instead of creating a new one.
    pub fn new(
        client: TelemetryServiceClient<Channel>,
        agent_id: String,
        node_name: String,
        pod_name: String,
        previous_session_id: Option<String>,
    ) -> Self {
        info!("Initialising connection manager");

        Self {
            client,
            agent_id,
            node_name,
            pod_name,
            session_id: previous_session_id,
        }
    }

    pub async fn connect(&mut self) -> Result<bool, ConnectionError> {
        let mut retry_delay = INITIAL_RECONNECT_DELAY;

        loop {
            debug!("Attempting to connect agent to controller");
            let mut request = Request::new(ConnectRequest {
                agent_id: self.agent_id.clone(),
                node_name: self.node_name.clone(),
                pod_name: self.pod_name.clone(),
            });
            add_reconnect_metadata(&mut request, &self.agent_id, self.session_id.as_deref())?;

            let result = match time::timeout(RPC_TIMEOUT, self.client.connect_agent(request)).await
            {
                Ok(result) => result,
                Err(_) => Err(Status::deadline_exceeded("ConnectAgent timed out")),
            };

            match result {
                Ok(response) => {
                    let response = response.into_inner();
                    if !response.success {
                        error!("Connection rejected by controller");
                        return Ok(false);
                    }

                    self.session_id = Some(response.session_id);
                    info!("Successfully connected to controller");
                    return Ok(true);
                }
                Err(status)
                    if matches!(
                        status.code(),
                        tonic::Code::Unavailable | tonic::Code::DeadlineExceeded
                    ) =>
                {
                    warn!(
                        "Controller unavailable ({}); retrying connection in {:?}",
                        status.code(),
                        retry_delay
                    );
                    time::sleep(retry_delay).await;
                    retry_delay = std::cmp::min(retry_delay * 2, MAX_RECONNECT_DELAY);
                }
                Err(status) => {
                    error!("Connection rejected with gRPC status {}", status.code());
                    return Err(ConnectionError::Grpc(Box::new(status)));
                }
            }
        }
    }

    /// Sends heartbeats until one fails. Only returns on failure.
    pub async fn start_heartbeat(&mut self) -> Result<(), ConnectionError> {
        let mut interval = time::interval(HEARTBEAT_INTERVAL);

        info!("Starting heartbeat with interval {:?}", HEARTBEAT_INTERVAL);

        loop {
            interval.tick().await;

            let Some(session_id) = &self.session_id else {
                error!("No session ID available for heartbeat");
                return Err(ConnectionError::Session("No active session".to_string()));
            };

            let request = Request::new(Heartbeat {
                agent_id: self.agent_id.clone(),
                session_id: session_id.clone(),
            });

            debug!("Sending heartbeat");

            let result = match time::timeout(RPC_TIMEOUT, self.client.send_heartbeat(request)).await
            {
                Ok(result) => result,
                Err(_) => Err(Status::deadline_exceeded("SendHeartbeat timed out")),
            };
            let status = match result {
                Ok(response) => response.into_inner(),
                Err(e) => {
                    error!("Failed to send heartbeat: {} ({})", e.message(), e.code());
                    return Err(ConnectionError::Grpc(Box::new(e)));
                }
            };

            match status.status {
                0 => debug!("Heartbeat acknowledged"), // CONNECTED
                1 => {
                    // DISCONNECTED
                    warn!("Controller reports disconnected state");
                    return Err(ConnectionError::Session(
                        "Disconnected by controller".to_string(),
                    ));
                }
                2 => {
                    // ERROR
                    let err_msg = format!("Heartbeat error: {}", status.error_message);
                    error!("{}", err_msg);
                    return Err(ConnectionError::Session(err_msg));
                }
                other => {
                    error!("Invalid status received in heartbeat response: {}", other);
                    return Err(ConnectionError::Session("Invalid status".to_string()));
                }
            }
        }
    }

    pub fn get_agent_id(&self) -> &str {
        &self.agent_id
    }

    pub fn get_session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    pub fn get_node_name(&self) -> &str {
        &self.node_name
    }

    pub fn get_pod_name(&self) -> &str {
        &self.pod_name
    }
}

fn add_reconnect_metadata<T>(
    request: &mut Request<T>,
    agent_id: &str,
    previous_session_id: Option<&str>,
) -> Result<(), ConnectionError> {
    let Some(session_id) = previous_session_id else {
        return Ok(());
    };

    let agent_id = MetadataValue::try_from(agent_id)
        .map_err(|error| ConnectionError::Metadata(error.to_string()))?;
    let session_id = MetadataValue::try_from(session_id)
        .map_err(|error| ConnectionError::Metadata(error.to_string()))?;
    request.metadata_mut().insert("x-agent-id", agent_id);
    request.metadata_mut().insert("x-session-id", session_id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::add_reconnect_metadata;
    use tonic::Request;

    #[test]
    fn omits_session_metadata_for_initial_connection() {
        let mut request = Request::new(());

        add_reconnect_metadata(&mut request, "agent-123", None).unwrap();

        assert!(request.metadata().get("x-agent-id").is_none());
        assert!(request.metadata().get("x-session-id").is_none());
    }

    #[test]
    fn includes_previous_session_metadata_when_reconnecting() {
        let mut request = Request::new(());

        add_reconnect_metadata(&mut request, "agent-123", Some("session-123")).unwrap();

        assert_eq!(request.metadata().get("x-agent-id").unwrap(), "agent-123");
        assert_eq!(
            request.metadata().get("x-session-id").unwrap(),
            "session-123"
        );
    }
}
