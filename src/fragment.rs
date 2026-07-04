use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    time::{Instant, Sleep},
};
use rand::Rng;

// ==========================================
// 4. TCP SNI FRAGMENTATION & DPI EXHAUSTION
// ==========================================
pub struct FragmentedStream {
    pub inner: TcpStream,
    bytes_written: usize,
    max_fragment_bytes: usize,
    delay_timer: Pin<Box<Sleep>>,
    is_delaying: bool,
    pass_through: bool,
}

impl FragmentedStream {
    pub fn new(inner: TcpStream) -> Self {
        Self {
            inner,
            bytes_written: 0,
            max_fragment_bytes: 512, // Usually enough to cover the TLS ClientHello
            // One-time allocation for the delay timer (not in the hot path)
            delay_timer: Box::pin(tokio::time::sleep(Duration::from_millis(0))),
            is_delaying: false,
            pass_through: false,
        }
    }
}

impl AsyncRead for FragmentedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for FragmentedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.pass_through || buf.is_empty() {
            return Pin::new(&mut self.inner).poll_write(cx, buf);
        }

        // If we are currently delaying between chunks, check the timer
        if self.is_delaying {
            match self.delay_timer.as_mut().poll(cx) {
                Poll::Ready(_) => {
                    self.is_delaying = false; // Delay is over, proceed to write
                }
                Poll::Pending => {
                    return Poll::Pending; // Still waiting for the delay
                }
            }
        }

        let mut rng = rand::thread_rng();
        // 1. Randomized Chunking: 1 to 40 bytes
        let chunk_size = rng.gen_range(1..=40);
        let write_len = std::cmp::min(buf.len(), chunk_size);

        match Pin::new(&mut self.inner).poll_write(cx, &buf[..write_len]) {
            Poll::Ready(Ok(n)) => {
                self.bytes_written += n;
                
                // If we've fragmented enough bytes, switch to pass-through
                if self.bytes_written >= self.max_fragment_bytes {
                    self.pass_through = true;
                } else if n > 0 {
                    // 2. Micro-Delays (Jitter): 5 to 30 ms
                    let delay_ms = rng.gen_range(5..=30);
                    self.delay_timer.as_mut().reset(Instant::now() + Duration::from_millis(delay_ms));
                    self.is_delaying = true;
                    
                    // We must poll the timer once to register the waker with the current context!
                    let _ = self.delay_timer.as_mut().poll(cx);
                }
                
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
