#![cfg(any(
    feature = "rustls",
    feature = "native-tls",
    feature = "vendored-openssl"
))]

use futures_util::io::{AsyncRead, AsyncWrite};
use once_cell::sync::Lazy;
use std::env;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tiberius::{Client, Config, EncryptionLevel, Result};
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncWriteCompatExt;

static CONN_STR: Lazy<String> = Lazy::new(|| {
    env::var("TIBERIUS_TEST_CONNECTION_STRING").unwrap_or_else(|_| {
        "server=tcp:localhost,1433;user=SA;password=<YourStrong@Passw0rd>;IntegratedSecurity=true;TrustServerCertificate=true".to_owned()
    })
});

/// A socket that is briefly not writable before every write.
struct PendingWrites<S> {
    inner: S,
    pend: bool,
}

impl<S: AsyncRead + Unpin> AsyncRead for PendingWrites<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PendingWrites<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.pend {
            self.pend = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.pend = true;
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

#[tokio::test]
async fn tls_handshake_survives_pending_writes() -> Result<()> {
    let mut config = Config::from_ado_string(&CONN_STR)?;
    config.encryption(EncryptionLevel::Required);
    let tcp = TcpStream::connect(config.get_addr()).await?;
    tcp.set_nodelay(true)?;
    let stream = PendingWrites {
        inner: tcp.compat_write(),
        pend: true,
    };

    let mut client = Client::connect(config, stream).await?;
    let row = client
        .query("SELECT @P1", &[&-4i32])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some(-4i32), row.get(0));

    Ok(())
}
