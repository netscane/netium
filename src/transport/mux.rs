use std::collections::HashMap;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::warn;
use yamux::{Config as YamuxConfig, Connection, Mode};

use crate::common::{IntoStream, Result, Stream};
use crate::error::Error;

/// Manages yamux client sessions per target key.
pub struct MuxManager {
    sessions: Mutex<HashMap<String, Arc<MuxSession>>>,
    config: YamuxConfig,
}

struct MuxSession {
    connection: Arc<Mutex<Connection<tokio_util::compat::Compat<Stream>>>>,
    _driver: JoinHandle<()>,
}

impl MuxManager {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            config: YamuxConfig::default(),
        }
    }

    /// Get or establish a mux stream for a target key.
    pub async fn get_stream<D, Fut>(&self, key: &str, dial: D) -> Result<Stream>
    where
        D: FnOnce() -> Fut + Send,
        Fut: std::future::Future<Output = Result<Stream>> + Send,
    {
        if let Some(stream) = self.try_open_existing(key).await? {
            return Ok(stream);
        }

        self.open_new(key, dial).await
    }

    async fn try_open_existing(&self, key: &str) -> Result<Option<Stream>> {
        let session = {
            let map = self.sessions.lock().await;
            map.get(key).cloned()
        };

        if let Some(sess) = session {
            match sess.open_stream().await {
                Ok(stream) => return Ok(Some(stream)),
                Err(e) => {
                    warn!("mux session for {} failed: {}", key, e);
                }
            }
            // drop the failed session
            let mut map = self.sessions.lock().await;
            map.remove(key);
        }

        Ok(None)
    }

    async fn open_new<D, Fut>(&self, key: &str, dial: D) -> Result<Stream>
    where
        D: FnOnce() -> Fut + Send,
        Fut: std::future::Future<Output = Result<Stream>> + Send,
    {
        let stream = dial().await?;
        let compat = stream.compat();

        let connection = Connection::new(compat, self.config.clone(), Mode::Client);
        let conn_arc = Arc::new(Mutex::new(connection));

        let mux = Arc::new(MuxSession {
            connection: conn_arc,
            _driver: tokio::spawn(async {}),
        });

        {
            let mut map = self.sessions.lock().await;
            map.insert(key.to_string(), mux.clone());
        }

        mux.open_stream().await
    }
}

impl MuxSession {
    async fn open_stream(&self) -> Result<Stream> {
        let stream = futures::future::poll_fn(|cx: &mut Context<'_>| {
            let mut conn = match self.connection.try_lock() {
                Ok(c) => c,
                Err(_) => return Poll::Pending,
            };
            conn.poll_new_outbound(cx)
        })
        .await
        .map_err(|e| Error::Transport(format!("mux open stream failed: {}", e)))?;

        Ok(stream.compat().into_stream())
    }
}
