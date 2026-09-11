//! Stable logical connection, independent of any one tool future or view.
//! Its owner supplies a factory that rehydrates current credentials on each launch.
use crate::McpClient;
use anyhow::{anyhow, Result};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, RwLock,
    },
};
use tokio::sync::Mutex;
use tracing::Instrument;

pub type ClientFactory =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Result<McpClient>> + Send>> + Send + Sync>;

pub struct ManagedConnection {
    identity: (String, String, String),
    factory: ClientFactory,
    current: RwLock<Option<Arc<McpClient>>>,
    connect: Mutex<Option<String>>,
    attempts: AtomicU64,
    generation: AtomicU64,
    registered_generation: AtomicU64,
    catalog_changed: AtomicBool,
    closed: AtomicBool,
}
impl ManagedConnection {
    pub fn new(factory: ClientFactory) -> Self {
        Self {
            identity: Default::default(),
            factory,
            current: RwLock::new(None),
            connect: Mutex::new(None),
            attempts: AtomicU64::new(0),
            generation: AtomicU64::new(0),
            registered_generation: AtomicU64::new(0),
            catalog_changed: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        }
    }
    pub fn with_identity(mut self, project: &str, frame: &str, connector: &str) -> Self {
        self.identity = (project.into(), frame.into(), connector.into());
        self
    }
    pub fn span(&self) -> tracing::Span {
        tracing::info_span!(target: "wisp", "mcp", project=%self.identity.0, frame=%self.identity.1, connector=%self.identity.2, generation=self.generation())
    }
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }
    pub fn needs_catalog_refresh(&self) -> bool {
        !self.is_connected()
            || self.catalog_changed.load(Ordering::SeqCst)
            || self.generation() != self.registered_generation.load(Ordering::SeqCst)
    }
    pub fn mark_catalog_current(&self) {
        self.registered_generation
            .store(self.generation(), Ordering::SeqCst);
        self.catalog_changed.store(false, Ordering::SeqCst);
    }
    pub fn catalog_changed(&self) {
        self.catalog_changed.store(true, Ordering::SeqCst);
    }
    pub fn is_connected(&self) -> bool {
        !self.closed.load(Ordering::SeqCst)
            && self
                .current
                .read()
                .unwrap()
                .as_ref()
                .is_some_and(|c| c.is_connected())
    }
    pub async fn ready(&self) -> Result<Arc<McpClient>> {
        let attempt = self.attempts.load(Ordering::SeqCst);
        let mut last_error = self.connect.lock().await;
        if self.closed.load(Ordering::SeqCst) {
            return Err(anyhow!(
                "MCP connector disabled or replaced; request not sent"
            ));
        }
        let previous = self.current.read().unwrap().clone();
        if let Some(client) = &previous {
            if client.is_connected() {
                return Ok(client.clone());
            }
        }
        if attempt != self.attempts.load(Ordering::SeqCst) {
            if let Some(message) = &*last_error {
                return Err(anyhow!(message.clone()));
            }
        }
        if let Some(client) = previous {
            let _ = Box::pin(client.shutdown()).await;
        }
        self.current.write().unwrap().take();
        self.generation.fetch_add(1, Ordering::SeqCst);
        tracing::info!(target: "wisp", generation=self.generation(), "mcp.connection.connecting");
        let result = tokio::select! {
            result = async {
                let client = (self.factory)().await?;
                Box::pin(client.tools_list()).await?;
                Ok::<_,anyhow::Error>(client)
            }.instrument(self.span()) => result,
            _ = async { loop {
                if self.closed.load(Ordering::SeqCst) { break; }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            } } => Err(anyhow!("MCP connector closed during initialization")),
        };
        self.attempts.fetch_add(1, Ordering::SeqCst);
        match result {
            Ok(client) => {
                if self.closed.load(Ordering::SeqCst) {
                    let _ = Box::pin(client.shutdown()).await;
                    return Err(anyhow!("MCP connector closed during initialization"));
                }
                let client = Arc::new(client);
                *self.current.write().unwrap() = Some(client.clone());
                *last_error = None;
                let generation = self.generation();
                tracing::info!(target: "wisp", generation, "mcp.connection.ready");
                Ok(client)
            }
            Err(error) => {
                *last_error = Some(error.to_string());
                tracing::warn!(target: "wisp", "mcp.connection.failed; next explicit use may retry");
                Err(error)
            }
        }
    }
    pub async fn shutdown(&self) -> Result<()> {
        // Reject new requests before waiting for a concurrent bounded initialization.
        self.closed.store(true, Ordering::SeqCst);
        let _connect = self.connect.lock().await;
        let client = self.current.write().unwrap().take();
        tracing::info!(target: "wisp", generation=self.generation(), "mcp.connection.shutdown");
        if let Some(client) = client {
            Box::pin(client.shutdown()).await?;
        }
        Ok(())
    }
}
