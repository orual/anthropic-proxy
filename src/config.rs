use anyhow::{Context, Result};
use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct Config {
    pub port: u16,
    pub session_secret: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub oauth_base_url: String,
    pub api_base_url: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        dotenvy::dotenv().ok();

        Ok(Self {
            port: std::env::var("PORT")
                .unwrap_or_else(|_| "4000".to_string())
                .parse()
                .context("Invalid PORT")?,

            session_secret: std::env::var("SESSION_SECRET").unwrap_or_else(|_| {
                // Generate a random secret if not provided
                use rand::Rng;
                let secret: Vec<u8> = (0..32).map(|_| rand::thread_rng().gen()).collect();
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, secret)
            }),

            client_id: std::env::var("CLIENT_ID")
                .unwrap_or_else(|_| "9d1c250a-e61b-44d9-88ed-5944d1962f5e".to_string()),

            redirect_uri: std::env::var("REDIRECT_URI").unwrap_or_else(|_| {
                "https://console.anthropic.com/oauth/code/callback".to_string()
            }),

            oauth_base_url: std::env::var("OAUTH_BASE_URL")
                .unwrap_or_else(|_| "https://claude.ai".to_string()),

            api_base_url: std::env::var("API_BASE_URL")
                .unwrap_or_else(|_| "https://api.anthropic.com/v1".to_string()),
        })
    }

    pub fn server_address(&self) -> SocketAddr {
        ([0, 0, 0, 0], self.port).into()
    }
}
