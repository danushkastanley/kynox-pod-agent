use std::time::Duration;
use tokio::time;
use tonic::transport::{Channel, Error as TransportError};
use tonic::{Request, Status};
use log::{info, error, warn, debug};
use uuid::Uuid;
use backoff::{Error, ExponentialBackoff};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::telemetry::{
    telemetry_service_client::TelemetryServiceClient,
    ConnectRequest, Heartbeat,
};

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(300); // 5 minutes
const INITIAL_RECONNECT_DELAY: Duration = Duration::from_secs(1);

#[derive(Debug)]
pub enum ConnectionError {
    Transport(TransportError),
    Grpc(Status),
    Session(String),
    Timeout,
}

impl std::fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "Transport error: {}", e),
            Self::Grpc(s) => write!(f, "gRPC error: {}", s),
            Self::Session(msg) => write!(f, "Session error: {}", msg),
            Self::Timeout => write!(f, "Connection timeout"),
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
    pub fn new(client: TelemetryServiceClient<Channel>, node_name: String, pod_name: String) -> Self {
        let agent_id = Uuid::new_v4().to_string();
        info!("Initializing ConnectionManager for agent {} on node {}", agent_id, node_name);
        
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
        let backoff = ExponentialBackoff {
            initial_interval: INITIAL_RECONNECT_DELAY,
            max_interval: MAX_RECONNECT_DELAY,
            multiplier: 2.0,
            max_elapsed_time: None,
            ..ExponentialBackoff::default()
        };

        let agent_id = Arc::new(self.agent_id.clone());
        let node_name = Arc::new(self.node_name.clone());
        let pod_name = Arc::new(self.pod_name.clone());
        let client = self.client.clone();
        let is_healthy = self.is_healthy.clone();

        let connect_operation = move || {
            let agent_id = Arc::clone(&agent_id);
            let node_name = Arc::clone(&node_name);
            let pod_name = Arc::clone(&pod_name);
            let mut client = client.clone();
            let is_healthy = is_healthy.clone();

            async move {
                debug!("Attempting to connect agent {} to controller...", *agent_id);
                
                let request = Request::new(ConnectRequest {
                    agent_id: (*agent_id).clone(),
                    node_name: (*node_name).clone(),
                    pod_name: (*pod_name).clone(),
                });

                match client.connect_agent(request).await {
                    Ok(response) => {
                        let response = response.into_inner();
                        if response.success {
                            let session_id = response.session_id;
                            is_healthy.store(true, Ordering::SeqCst);
                            
                            info!("Successfully connected to controller (session: {})", session_id);
                            debug!("Connection details:");
                            debug!("  Agent ID: {}", *agent_id);
                            debug!("  Node: {}", *node_name);
                            debug!("  Pod: {}", *pod_name);
                            
                            Ok((true, Some(session_id)))
                        } else {
                            let err_msg = format!("Connection rejected by controller: {}", response.error_message);
                            error!("{}", err_msg);
                            Ok((false, None))
                        }
                    }
                    Err(status) => {
                        error!("Connection attempt failed:");
                        error!("   Error Code: {}", status.code());
                        error!("   Message: {}", status.message());
                        error!("   Details: {:?}", status.details());
                        
                        if status.code() == tonic::Code::Unavailable {
                            Err(Error::transient(ConnectionError::Grpc(status)))
                        } else {
                            Err(Error::permanent(ConnectionError::Grpc(status)))
                        }
                    }
                }
            }
        };

        match backoff::future::retry(backoff, connect_operation).await {
            Ok((success, session_id)) => {
                self.session_id = session_id;
                Ok(success)
            }
            Err(e) => Err(e),
        }
    }

    pub async fn start_heartbeat(&mut self) -> Result<(), ConnectionError> {
        let mut interval = time::interval(HEARTBEAT_INTERVAL);
        
        info!("Starting heartbeat for agent {} with interval {:?}", self.agent_id, HEARTBEAT_INTERVAL);

        loop {
            interval.tick().await;

            if let Some(session_id) = &self.session_id {
                let request = Request::new(Heartbeat {
                    agent_id: self.agent_id.clone(),
                    session_id: session_id.clone(),
                });

                debug!("Sending heartbeat for session {}", session_id);

                match self.client.send_heartbeat(request).await {
                    Ok(response) => {
                        let status = response.into_inner();
                        match status.status {
                            0 => { // CONNECTED
                                debug!("Heartbeat acknowledged");
                                self.is_healthy.store(true, Ordering::SeqCst);
                            }
                            2 => { // ERROR
                                self.is_healthy.store(false, Ordering::SeqCst);
                                let err_msg = format!("Heartbeat error: {}", status.error_message);
                                error!("{}", err_msg);
                                error!("   Session ID: {}", session_id);
                                error!("   Agent ID: {}", self.agent_id);
                                return Err(ConnectionError::Session(err_msg));
                            }
                            1 => { // DISCONNECTED
                                self.is_healthy.store(false, Ordering::SeqCst);
                                warn!("Controller reports disconnected state");
                                warn!("   Session ID: {}", session_id);
                                warn!("   Agent ID: {}", self.agent_id);
                                return Err(ConnectionError::Session("Disconnected by controller".to_string()));
                            }
                            _ => {
                                self.is_healthy.store(false, Ordering::SeqCst);
                                error!("Invalid status received in heartbeat response");
                                error!("   Status: {}", status.status);
                                error!("   Session ID: {}", session_id);
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
                        error!("   Session ID: {}", session_id);
                        error!("   Agent ID: {}", self.agent_id);
                        return Err(ConnectionError::Grpc(e));
                    }
                }
            } else {
                self.is_healthy.store(false, Ordering::SeqCst);
                error!("No session ID available for heartbeat");
                error!("   Agent ID: {}", self.agent_id);
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