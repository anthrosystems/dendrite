use serde::Serialize;
use std::net::TcpStream;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use tungstenite::Message;
use tungstenite::protocol::WebSocket;

/// Broadcasts live daemon events (ingestion pipeline snapshots, HTTP
/// mutation notifications) to connected WebSocket clients.
///
/// This no longer owns a `TcpListener` of its own: the WebSocket endpoint
/// (`/ws`) shares the HTTP API's single TCP listener/port rather than
/// binding a separate `DENDRITE_WS_ADDR` port, so that distribution
/// packaging only needs to expose one address for both (see
/// `http::complete_websocket_upgrade`, which performs the handshake and
/// hands the resulting connection to `accept_websocket` below).
#[derive(Clone, Default)]
pub struct LiveBroadcaster {
    subscribers: Arc<Mutex<Vec<mpsc::SyncSender<String>>>>,
}

impl LiveBroadcaster {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers an already-handshaken WebSocket connection as a subscriber
    /// and spawns a dedicated thread that forwards published events to it
    /// until the client disconnects or a write fails. The handshake itself
    /// (reading the upgrade request, writing the `101` response) has
    /// already happened by the time this is called — see
    /// `http::complete_websocket_upgrade`.
    pub fn accept_websocket(&self, mut websocket: WebSocket<TcpStream>) {
        let subscribers = Arc::clone(&self.subscribers);
        if let Err(error) = thread::Builder::new()
            .name("dendrite-live-client".into())
            .spawn(move || {
                let (tx, rx) = mpsc::sync_channel::<String>(512);
                if let Ok(mut list) = subscribers.lock() {
                    list.push(tx);
                }
                while let Ok(payload) = rx.recv() {
                    if websocket.write(Message::Text(payload.into())).is_err() {
                        break;
                    }
                }
            })
        {
            eprintln!("failed to start WebSocket client worker: {error}");
        }
    }

    pub fn publish<T: Serialize>(&self, kind: &str, payload: &T) {
        // Skip the JSON serialization entirely when nobody's listening — this
        // runs on the hot ingestion path, once per processed observation, so
        // paying for it unconditionally (as before) means real, avoidable CPU
        // cost on every single event whenever no UI/WebSocket client is
        // connected, which is the common case for unattended operation.
        let has_subscribers = self
            .subscribers
            .lock()
            .map(|subscribers| !subscribers.is_empty())
            .unwrap_or(false);
        if !has_subscribers {
            return;
        }

        let Ok(message) = serde_json::to_string(&serde_json::json!({
            "kind": kind,
            "payload": payload,
        })) else {
            return;
        };

        if let Ok(mut subscribers) = self.subscribers.lock() {
            subscribers.retain(|subscriber| match subscriber.try_send(message.clone()) {
                Ok(()) | Err(mpsc::TrySendError::Full(_)) => true,
                Err(mpsc::TrySendError::Disconnected(_)) => false,
            });
        }
    }
}
