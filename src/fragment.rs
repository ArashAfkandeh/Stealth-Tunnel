use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};

// ==========================================
// 4. TCP SNI FRAGMENTATION
// ==========================================
pub struct FragmentedStream {
    pub inner: TcpStream,
    pub first_write: bool,
}

impl AsyncRead for FragmentedStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> { Pin::new(&mut self.inner).poll_read(cx, buf) }
}
impl AsyncWrite for FragmentedStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        if !self.first_write {
            self.first_write = true;
            return Pin::new(&mut self.inner).poll_write(cx, &buf[..std::cmp::min(3, buf.len())]);
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> { Pin::new(&mut self.inner).poll_flush(cx) }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> { Pin::new(&mut self.inner).poll_shutdown(cx) }
}
