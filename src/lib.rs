pub mod config;
pub mod debounce;
pub mod heartbeat;
pub mod matrix;
pub mod routes;
pub mod ssrf;
pub mod webpush;

use std::sync::Arc;

use tokio::sync::Semaphore;

use crate::config::Config;
use crate::debounce::DebounceStore;
use crate::heartbeat::HeartbeatStore;
use crate::webpush::PushTransport;
use crate::webpush::vapid::VapidKey;

/// Shared application state cloned cheaply into Axum handlers.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub vapid: Arc<VapidKey>,
    pub heartbeats: Arc<HeartbeatStore>,
    pub debounce: Arc<DebounceStore>,
    pub transport: Arc<dyn PushTransport>,
    pub push_semaphore: Arc<Semaphore>,
}
