use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use log::{debug, error, info, warn};
use tokio::time;
use tonic::metadata::MetadataValue;
use tonic::transport::Channel;
use tonic::{Request, Status};
use uuid::Uuid;

use crate::telemetry::{
    telemetry_service_client::TelemetryServiceClient, ConnectRequest, Heartbeat,
};

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(300); // 5 minutes
const INITIAL_RECONNECT_DELAY: Duration = Duration::from_secs(1);

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
    is_healthy: std::sync::Arc<AtomicBool>,
}

impl ConnectionManager {
    pub fn new(
        client: TelemetryServiceClient<Channel>,
        node_name: String,
        pod_name: String,
    ) -> Self {
        let agent_id = Uuid::new_v4().to_string();
        info!("Initialising connection manager");

        Self {
            client,
            agent_id,
            node_name,
            pod_name,
            session_id: None,
            is_healthy: std::sync::Arc::new(AtomicBool::new(false)),
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

            match self.client.connect_agent(request).await {
                Ok(response) => {
                    let response = response.into_inner();
                    if !response.success {
                        self.is_healthy.store(false, Ordering::SeqCst);
                        error!("Connection rejected by controller");
                        return Ok(false);
                    }

                    self.session_id = Some(response.session_id);
                    self.is_healthy.store(true, Ordering::SeqCst);
                    info!("Successfully connected to controller");
                    return Ok(true);
                }
                Err(status) if status.code() == tonic::Code::Unavailable => {
                    self.is_healthy.store(false, Ordering::SeqCst);
                    warn!(
                        "Controller unavailable; retrying connection in {:?}",
                        retry_delay
                    );
                    time::sleep(retry_delay).await;
                    retry_delay = std::cmp::min(retry_delay * 2, MAX_RECONNECT_DELAY);
                }
                Err(status) => {
                    self.is_healthy.store(false, Ordering::SeqCst);
                    error!("Connection rejected with gRPC status {}", status.code());
                    return Err(ConnectionError::Grpc(Box::new(status)));
                }
            }
        }
    }

    pub async fn start_heartbeat(&mut self) -> Result<(), ConnectionError> {
        let mut interval = time::interval(HEARTBEAT_INTERVAL);

        info!("Starting heartbeat with interval {:?}", HEARTBEAT_INTERVAL);

        loop {
            interval.tick().await;

            if let Some(session_id) = &self.session_id {
                let request = Request::new(Heartbeat {
                    agent_id: self.agent_id.clone(),
                    session_id: session_id.clone(),
                });

                debug!("Sending heartbeat");

                match self.client.send_heartbeat(request).await {
                    Ok(response) => {
                        let status = response.into_inner();
                        match status.status {
                            0 => {
                                // CONNECTED
                                debug!("Heartbeat acknowledged");
                                self.is_healthy.store(true, Ordering::SeqCst);
                            }
                            2 => {
                                // ERROR
                                self.is_healthy.store(false, Ordering::SeqCst);
                                let err_msg = format!("Heartbeat error: {}", status.error_message);
                                error!("{}", err_msg);
                                return Err(ConnectionError::Session(err_msg));
                            }
                            1 => {
                                // DISCONNECTED
                                self.is_healthy.store(false, Ordering::SeqCst);
                                warn!("Controller reports disconnected state");
                                return Err(ConnectionError::Session(
                                    "Disconnected by controller".to_string(),
                                ));
                            }
                            _ => {
                                self.is_healthy.store(false, Ordering::SeqCst);
                                error!("Invalid status received in heartbeat response");
                                error!("   Status: {}", status.status);
                                return Err(ConnectionError::Session("Invalid status".to_string()));
                            }
                        }
                    }
                    Err(e) => {
                        self.is_healthy.store(false, Ordering::SeqCst);
                        error!("Failed to send heartbeat:");
                        error!("   Error: {}", e);
                        error!("   Code: {}", e.code());
                        error!("   Message: {}", e.message());
                        return Err(ConnectionError::Grpc(Box::new(e)));
                    }
                }
            } else {
                self.is_healthy.store(false, Ordering::SeqCst);
                error!("No session ID available for heartbeat");
                return Err(ConnectionError::Session("No active session".to_string()));
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

    pub fn is_connected(&self) -> bool {
        self.session_id.is_some() && self.is_healthy.load(Ordering::SeqCst)
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
