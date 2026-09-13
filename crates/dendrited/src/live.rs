use serde::Serialize;
use std::io;
use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;
use tungstenite::{Message, accept};

#[derive(Clone, Default)]
pub struct LiveBroadcaster {
    subscribers: Arc<Mutex<Vec<mpsc::SyncSender<String>>>>,
}

impl LiveBroadcaster {
    pub fn start(addr: SocketAddr) -> io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;
        let broadcaster = Self::default();
        let subscribers = Arc::clone(&broadcaster.subscribers);

        let _acceptor = thread::Builder::new()
            .name("dendrite-live-ws".into())
            .spawn(move || {
                loop {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let subscribers = Arc::clone(&subscribers);
                            if let Err(error) = thread::Builder::new()
                                .name("dendrite-live-client".into())
                                .spawn(move || {
                                    let Ok(mut websocket) = accept(stream) else {
                                        return;
                                    };
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
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(25));
                        }
                        Err(error) => {
                            eprintln!("WebSocket listener failed: {error}");
                            thread::sleep(Duration::from_millis(250));
                        }
                    }
                }
            })?;

        Ok(broadcaster)
    }

    pub fn publish<T: Serialize>(&self, kind: &str, payload: &T) {
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
