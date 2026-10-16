#[cfg(any(
    feature = "rustls",
    feature = "native-tls",
    feature = "vendored-openssl"
))]
use super::tls_stream::TlsStream;
use crate::tds::{
    codec::{Decode, Encode, PacketHeader, PacketStatus, PacketType},
    HEADER_BYTES,
};
use bytes::BytesMut;
use futures_util::io::{AsyncRead, AsyncWrite};
use futures_util::ready;
use std::{
    cmp, io, mem,
    pin::Pin,
    task::{self, Poll},
};
use tracing::{event, Level};

/// A wrapper to handle either TLS or bare connections.
pub(crate) enum MaybeTlsStream<S: AsyncRead + AsyncWrite + Unpin + Send> {
    Raw(S),
    #[cfg(any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    ))]
    Tls(TlsStream<TlsPreloginWrapper<S>>),
}

#[cfg(any(
    feature = "rustls",
    feature = "native-tls",
    feature = "vendored-openssl"
))]
impl<S: AsyncRead + AsyncWrite + Unpin + Send> MaybeTlsStream<S> {
    pub fn into_inner(self) -> S {
        match self {
            Self::Raw(s) => s,
            #[cfg(any(
                feature = "rustls",
                feature = "native-tls",
                feature = "vendored-openssl"
            ))]
            Self::Tls(mut tls) => {
                let wrapper = tls.get_mut();
                debug_assert!(wrapper.out_buf.is_empty());
                wrapper.stream.take().unwrap()
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncRead for MaybeTlsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            MaybeTlsStream::Raw(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(any(
                feature = "rustls",
                feature = "native-tls",
                feature = "vendored-openssl"
            ))]
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncWrite for MaybeTlsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            MaybeTlsStream::Raw(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(any(
                feature = "rustls",
                feature = "native-tls",
                feature = "vendored-openssl"
            ))]
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Raw(s) => Pin::new(s).poll_flush(cx),
            #[cfg(any(
                feature = "rustls",
                feature = "native-tls",
                feature = "vendored-openssl"
            ))]
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Raw(s) => Pin::new(s).poll_close(cx),
            #[cfg(any(
                feature = "rustls",
                feature = "native-tls",
                feature = "vendored-openssl"
            ))]
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_close(cx),
        }
    }
}

/// On TLS handshake, the server expects to get and sends back normal TDS
/// packets. To use a common TLS library, we must implement a wrapper for
/// packet handling on this stage.
///
/// What it does is it interferes on handshake for TDS packet handling,
/// and when complete, just passes the calls to the underlying connection.
///
/// The underlying stream's `poll_flush` must not return `Pending` during the
/// handshake.
pub(crate) struct TlsPreloginWrapper<S> {
    stream: Option<S>,
    pending_handshake: bool,

    header_buf: [u8; HEADER_BYTES],
    header_pos: usize,
    read_remaining: usize,

    wr_buf: Vec<u8>,
    out_buf: Vec<u8>,
    out_pos: usize,
}

#[cfg(any(
    feature = "rustls",
    feature = "native-tls",
    feature = "vendored-openssl"
))]
impl<S> TlsPreloginWrapper<S> {
    pub fn new(stream: S) -> Self {
        TlsPreloginWrapper {
            stream: Some(stream),
            pending_handshake: true,

            header_buf: [0u8; HEADER_BYTES],
            header_pos: 0,
            read_remaining: 0,
            wr_buf: vec![0u8; HEADER_BYTES],
            out_buf: Vec::new(),
            out_pos: 0,
        }
    }

    pub fn handshake_complete(&mut self) {
        self.pending_handshake = false;
    }
}

impl<S: AsyncWrite + Unpin> TlsPreloginWrapper<S> {
    fn poll_send_queued(&mut self, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        while self.out_pos < self.out_buf.len() {
            let written = ready!(Pin::new(self.stream.as_mut().unwrap())
                .poll_write(cx, &self.out_buf[self.out_pos..]))?;

            if written == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }

            self.out_pos += written;
        }

        self.out_buf.clear();
        self.out_pos = 0;

        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncRead for TlsPreloginWrapper<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.poll_send_queued(cx))?;

        // Normal operation does not need any extra treatment, we handle packets
        // in the codec.
        if !self.pending_handshake {
            return Pin::new(&mut self.stream.as_mut().unwrap()).poll_read(cx, buf);
        }

        let inner = self.get_mut();

        // Read the headers separately and do not send them to the Tls
        // connection handling.
        if !inner.header_buf[inner.header_pos..].is_empty() {
            while !inner.header_buf[inner.header_pos..].is_empty() {
                let read = ready!(Pin::new(inner.stream.as_mut().unwrap())
                    .poll_read(cx, &mut inner.header_buf[inner.header_pos..]))?;

                if read == 0 {
                    return Poll::Ready(Ok(0));
                }

                inner.header_pos += read;
            }

            let header = PacketHeader::decode(&mut BytesMut::from(&inner.header_buf[..]))
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;

            // We only get pre-login packets in the handshake process.
            assert_eq!(header.r#type(), PacketType::PreLogin);

            // And we know from this point on how much data we should expect
            inner.read_remaining = header.length() as usize - HEADER_BYTES;

            event!(
                Level::TRACE,
                "Reading packet of {} bytes",
                inner.read_remaining,
            );
        }

        let max_read = cmp::min(inner.read_remaining, buf.len());

        // TLS connector gets whatever we have after the header.
        let read = ready!(
            Pin::new(&mut inner.stream.as_mut().unwrap()).poll_read(cx, &mut buf[..max_read])
        )?;

        inner.read_remaining -= read;

        // All data is read, after this we're expecting a new header.
        if inner.read_remaining == 0 {
            inner.header_pos = 0;
        }

        Poll::Ready(Ok(read))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncWrite for TlsPreloginWrapper<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.poll_send_queued(cx))?;

        // Normal operation does not need any extra treatment, we handle
        // packets in the codec.
        if !self.pending_handshake {
            return Pin::new(&mut self.stream.as_mut().unwrap()).poll_write(cx, buf);
        }

        // Buffering data.
        self.wr_buf.extend_from_slice(buf);

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        let inner = self.get_mut();

        if !inner.pending_handshake {
            ready!(inner.poll_send_queued(cx))?;
            return Pin::new(&mut inner.stream.as_mut().unwrap()).poll_flush(cx);
        }

        // If on handshake mode, wraps the data to a TDS packet before sending.
        if inner.wr_buf.len() > HEADER_BYTES {
            debug_assert!(inner.out_buf.is_empty());

            let mut header = PacketHeader::new(inner.wr_buf.len(), 0);

            header.set_type(PacketType::PreLogin);
            header.set_status(PacketStatus::EndOfMessage);

            header
                .encode(&mut &mut inner.wr_buf[0..HEADER_BYTES])
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "Could not encode header.")
                })?;

            event!(
                Level::TRACE,
                "Framing a packet of {} bytes",
                inner.wr_buf.len(),
            );

            inner.out_buf = mem::replace(&mut inner.wr_buf, vec![0u8; HEADER_BYTES]);
        }

        // rust-openssl cannot retry a pending flush, so the packet stays
        // queued and goes out before the next read or write.
        match inner.poll_send_queued(cx) {
            Poll::Ready(result) => result?,
            Poll::Pending => {
                event!(
                    Level::DEBUG,
                    "Deferring {} bytes of the TLS handshake",
                    inner.out_buf.len() - inner.out_pos,
                );

                return Poll::Ready(Ok(()));
            }
        }

        Pin::new(&mut inner.stream.as_mut().unwrap()).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_send_queued(cx))?;
        Pin::new(&mut self.stream.as_mut().unwrap()).poll_close(cx)
    }
}

#[cfg(all(
    test,
    any(
        feature = "rustls",
        feature = "native-tls",
        feature = "vendored-openssl"
    )
))]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::task::Waker;

    enum Write {
        Pending,
        Accept(usize),
        Fail(io::ErrorKind),
    }

    #[derive(Default)]
    struct Socket {
        writes: VecDeque<Write>,
        written: Vec<u8>,
        readable: VecDeque<u8>,
    }

    impl AsyncRead for Socket {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut task::Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            if self.readable.is_empty() {
                return Poll::Pending;
            }

            let read = cmp::min(buf.len(), self.readable.len());

            for (slot, byte) in buf.iter_mut().zip(self.readable.drain(..read)) {
                *slot = byte;
            }

            Poll::Ready(Ok(read))
        }
    }

    impl AsyncWrite for Socket {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut task::Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let accepted = match self.writes.pop_front() {
                None => buf.len(),
                Some(Write::Pending) => return Poll::Pending,
                Some(Write::Accept(n)) => cmp::min(n, buf.len()),
                Some(Write::Fail(kind)) => return Poll::Ready(Err(kind.into())),
            };

            self.written.extend_from_slice(&buf[..accepted]);

            Poll::Ready(Ok(accepted))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut task::Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _: &mut task::Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn wrapper(writes: impl IntoIterator<Item = Write>) -> TlsPreloginWrapper<Socket> {
        TlsPreloginWrapper::new(Socket {
            writes: writes.into_iter().collect(),
            ..Socket::default()
        })
    }

    fn packet(payload: &[u8]) -> Vec<u8> {
        let length = (HEADER_BYTES + payload.len()) as u16;
        let mut packet = vec![0x12, 0x01];
        packet.extend_from_slice(&length.to_be_bytes());
        packet.extend_from_slice(&[0, 0, 0, 0]);
        packet.extend_from_slice(payload);
        packet
    }

    fn socket(wrapper: &mut TlsPreloginWrapper<Socket>) -> &mut Socket {
        wrapper.stream.as_mut().unwrap()
    }

    fn write(wrapper: &mut TlsPreloginWrapper<Socket>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(wrapper).poll_write(&mut task::Context::from_waker(Waker::noop()), buf)
    }

    fn flush(wrapper: &mut TlsPreloginWrapper<Socket>) -> Poll<io::Result<()>> {
        Pin::new(wrapper).poll_flush(&mut task::Context::from_waker(Waker::noop()))
    }

    fn read(wrapper: &mut TlsPreloginWrapper<Socket>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        Pin::new(wrapper).poll_read(&mut task::Context::from_waker(Waker::noop()), buf)
    }

    #[test]
    fn deferred_flush_sends_the_packet_before_the_next_read() {
        let mut wrapper = wrapper([Write::Pending]);

        assert!(matches!(write(&mut wrapper, b"hello"), Poll::Ready(Ok(5))));
        assert!(matches!(flush(&mut wrapper), Poll::Ready(Ok(()))));
        assert!(socket(&mut wrapper).written.is_empty());

        socket(&mut wrapper).readable.extend(packet(b"abc"));
        let mut buf = [0u8; 16];

        assert!(matches!(read(&mut wrapper, &mut buf), Poll::Ready(Ok(3))));
        assert_eq!(b"abc", &buf[..3]);
        assert_eq!(packet(b"hello"), socket(&mut wrapper).written);
    }

    #[test]
    fn queued_packet_precedes_the_first_write_after_the_handshake() {
        let mut wrapper = wrapper([Write::Pending]);

        assert!(matches!(write(&mut wrapper, b"hello"), Poll::Ready(Ok(5))));
        assert!(matches!(flush(&mut wrapper), Poll::Ready(Ok(()))));

        wrapper.handshake_complete();

        assert!(matches!(write(&mut wrapper, b"login"), Poll::Ready(Ok(5))));

        let mut expected = packet(b"hello");
        expected.extend_from_slice(b"login");
        assert_eq!(expected, socket(&mut wrapper).written);
    }

    #[test]
    fn next_flight_gets_its_own_header_after_a_deferred_flush() {
        let mut wrapper = wrapper([Write::Pending]);

        assert!(matches!(write(&mut wrapper, b"one"), Poll::Ready(Ok(3))));
        assert!(matches!(flush(&mut wrapper), Poll::Ready(Ok(()))));
        assert!(matches!(write(&mut wrapper, b"second"), Poll::Ready(Ok(6))));
        assert!(matches!(flush(&mut wrapper), Poll::Ready(Ok(()))));

        let mut expected = packet(b"one");
        expected.extend(packet(b"second"));
        assert_eq!(expected, socket(&mut wrapper).written);
    }

    #[test]
    fn repeated_handshake_flush_keeps_the_packet_queued() {
        let mut wrapper = wrapper([Write::Pending, Write::Pending]);

        assert!(matches!(write(&mut wrapper, b"hello"), Poll::Ready(Ok(5))));
        assert!(matches!(flush(&mut wrapper), Poll::Ready(Ok(()))));
        assert!(matches!(flush(&mut wrapper), Poll::Ready(Ok(()))));
        assert!(socket(&mut wrapper).written.is_empty());
        assert!(matches!(flush(&mut wrapper), Poll::Ready(Ok(()))));
        assert_eq!(packet(b"hello"), socket(&mut wrapper).written);
    }

    #[test]
    fn handshake_write_waits_for_the_queued_packet() {
        let mut wrapper = wrapper([Write::Pending, Write::Pending]);

        assert!(matches!(write(&mut wrapper, b"one"), Poll::Ready(Ok(3))));
        assert!(matches!(flush(&mut wrapper), Poll::Ready(Ok(()))));
        assert!(write(&mut wrapper, b"second").is_pending());
        assert!(matches!(write(&mut wrapper, b"second"), Poll::Ready(Ok(6))));
        assert!(matches!(flush(&mut wrapper), Poll::Ready(Ok(()))));

        let mut expected = packet(b"one");
        expected.extend(packet(b"second"));
        assert_eq!(expected, socket(&mut wrapper).written);
    }

    #[test]
    fn short_writes_produce_the_exact_packet() {
        let mut wrapper = wrapper((0..10).map(|_| Write::Accept(3)));

        assert!(matches!(
            write(&mut wrapper, b"hello world"),
            Poll::Ready(Ok(11))
        ));
        assert!(matches!(flush(&mut wrapper), Poll::Ready(Ok(()))));
        assert_eq!(packet(b"hello world"), socket(&mut wrapper).written);
    }

    #[test]
    fn read_sends_the_rest_of_a_partially_written_packet() {
        let mut wrapper = wrapper([Write::Accept(5), Write::Pending]);

        assert!(matches!(
            write(&mut wrapper, b"hello world"),
            Poll::Ready(Ok(11))
        ));
        assert!(matches!(flush(&mut wrapper), Poll::Ready(Ok(()))));
        assert_eq!(packet(b"hello world")[..5], socket(&mut wrapper).written);

        socket(&mut wrapper).readable.extend(packet(b"abc"));
        let mut buf = [0u8; 16];

        assert!(matches!(read(&mut wrapper, &mut buf), Poll::Ready(Ok(3))));
        assert_eq!(packet(b"hello world"), socket(&mut wrapper).written);
    }

    #[test]
    fn read_reports_a_failed_deferred_send() {
        let mut wrapper = wrapper([Write::Pending, Write::Fail(io::ErrorKind::ConnectionReset)]);

        assert!(matches!(write(&mut wrapper, b"hello"), Poll::Ready(Ok(5))));
        assert!(matches!(flush(&mut wrapper), Poll::Ready(Ok(()))));

        let mut buf = [0u8; 16];

        match read(&mut wrapper, &mut buf) {
            Poll::Ready(Err(err)) => assert_eq!(io::ErrorKind::ConnectionReset, err.kind()),
            other => panic!("expected a connection reset, got {other:?}"),
        }
    }

    #[test]
    fn only_a_handshake_flush_defers_a_pending_send() {
        let mut wrapper = wrapper([Write::Pending, Write::Pending]);

        assert!(matches!(write(&mut wrapper, b"hello"), Poll::Ready(Ok(5))));
        assert!(matches!(flush(&mut wrapper), Poll::Ready(Ok(()))));

        wrapper.handshake_complete();

        assert!(flush(&mut wrapper).is_pending());
        assert!(matches!(flush(&mut wrapper), Poll::Ready(Ok(()))));
        assert_eq!(packet(b"hello"), socket(&mut wrapper).written);
    }
}
