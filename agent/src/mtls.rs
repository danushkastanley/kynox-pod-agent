use std::env;

use tonic::transport::{Certificate, ClientTlsConfig, Identity};

use crate::BoxError;

#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub controller_endpoint: String,
    pub mtls_enabled: bool,
    pub mtls_server_name: String,
    mtls_ca_cert_file: String,
    mtls_client_cert_file: String,
    mtls_client_key_file: String,
}

impl AgentConfig {
    pub fn load() -> Self {
        let controller_endpoint = env::var("CONTROLLER_ENDPOINT")
            .unwrap_or_else(|_| "rasp-controller.default.svc:50051".to_string());
        let mtls_server_name = env::var("MTLS_SERVER_NAME")
            .unwrap_or_else(|_| derive_tls_server_name(&controller_endpoint));

        Self {
            controller_endpoint,
            mtls_enabled: env::var("MTLS_ENABLED").unwrap_or_else(|_| "true".to_string())
                != "false",
            mtls_server_name,
            mtls_ca_cert_file: env::var("MTLS_CA_CERT_FILE")
                .unwrap_or_else(|_| "/etc/rasp/tls/ca/ca.crt".to_string()),
            mtls_client_cert_file: env::var("MTLS_CLIENT_CERT_FILE")
                .unwrap_or_else(|_| "/etc/rasp/tls/client/tls.crt".to_string()),
            mtls_client_key_file: env::var("MTLS_CLIENT_KEY_FILE")
                .unwrap_or_else(|_| "/etc/rasp/tls/client/tls.key".to_string()),
        }
    }
}

pub fn controller_uri(config: &AgentConfig) -> String {
    let host = config
        .controller_endpoint
        .trim_start_matches("https://")
        .trim_start_matches("http://");

    if config.mtls_enabled {
        format!("https://{}", host)
    } else {
        format!("http://{}", host)
    }
}

pub fn load_client_tls_config(config: &AgentConfig) -> Result<ClientTlsConfig, BoxError> {
    let ca_cert = std::fs::read(&config.mtls_ca_cert_file)?;
    let client_cert = std::fs::read(&config.mtls_client_cert_file)?;
    let client_key = std::fs::read(&config.mtls_client_key_file)?;

    Ok(ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(ca_cert))
        .identity(Identity::from_pem(client_cert, client_key))
        .domain_name(config.mtls_server_name.clone()))
}

fn derive_tls_server_name(endpoint: &str) -> String {
    endpoint
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split(':')
        .next()
        .unwrap_or(endpoint)
        .to_string()
}
