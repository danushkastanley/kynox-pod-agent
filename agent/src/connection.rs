use std::time::Duration;
use tokio::time;
use tonic::{transport::Channel, Request};
use log::{info, error, warn};
use uuid::Uuid;
use anyhow::Error as AnyhowError;

use crate::telemetry::{
    telemetry_service_client::TelemetryServiceClient,
    ConnectRequest, Heartbeat,
};

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub struct ConnectionManager {
    client: TelemetryServiceClient<Channel>,
    agent_id: String,
    node_name: String,
    pod_name: String,
    session_id: Option<String>,
}

impl ConnectionManager {
    pub fn new(client: TelemetryServiceClient<Channel>, node_name: String, pod_name: String) -> Self {
        let agent_id = Uuid::new_v4().to_string();
        Self {
            client,
            agent_id,
            node_name,
            pod_name,
            session_id: None,
        }
    }

    pub async fn connect(&mut self) -> Result<bool, AnyhowError> {
        let request = Request::new(ConnectRequest {
            agent_id: self.agent_id.clone(),
            node_name: self.node_name.clone(),
            pod_name: self.pod_name.clone(),
        });

        match self.client.connect_agent(request).await {
            Ok(response) => {
                let response = response.into_inner();
                if response.success {
                    let session_id = response.session_id;
                    self.session_id = Some(session_id.clone());
                    info!("Successfully connected to controller with session ID: {}", session_id);
                    Ok(true)
                } else {
                    error!("Connection failed: {}", response.error_message);
                    Ok(false)
                }
            }
            Err(e) => {
                error!("Failed to connect to controller: {}", e);
                Err(e.into())
            }
        }
    }

    pub async fn start_heartbeat(&mut self) -> Result<(), AnyhowError> {
        let mut interval = time::interval(HEARTBEAT_INTERVAL);

        loop {
            interval.tick().await;

            if let Some(session_id) = &self.session_id {
                let request = Request::new(Heartbeat {
                    agent_id: self.agent_id.clone(),
                    session_id: session_id.clone(),
                });

                match self.client.send_heartbeat(request).await {
                    Ok(response) => {
                        let status = response.into_inner();
                        match status.status {
                            0 => { // CONNECTED
                                info!("Heartbeat successful");
                            }
                            2 => { // ERROR
                                error!("Heartbeat error: {}", status.error_message);
                                return Err(anyhow::anyhow!("Connection lost"));
                            }
                            1 => { // DISCONNECTED
                                warn!("Controller reports disconnected state");
                                return Err(anyhow::anyhow!("Disconnected by controller"));
                            }
                            _ => {
                                error!("Invalid status received");
                                return Err(anyhow::anyhow!("Invalid status"));
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to send heartbeat: {}", e);
                        return Err(e.into());
                    }
                }
            } else {
                error!("No session ID available for heartbeat");
                return Err(anyhow::anyhow!("No active session"));
            }
        }
    }

    pub fn get_agent_id(&self) -> &str {
        &self.agent_id
    }

    pub fn get_session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    pub fn is_connected(&self) -> bool {
        self.session_id.is_some()
    }
}
