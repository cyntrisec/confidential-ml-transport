use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};

/// Connect to a TCP endpoint.
pub async fn connect(addr: SocketAddr) -> std::io::Result<TcpStream> {
    let stream = TcpStream::connect(addr).await?;
    stream.set_nodelay(true)?;
    Ok(stream)
}

/// Bind a TCP listener and return it.
pub async fn listen(addr: SocketAddr) -> std::io::Result<TcpListener> {
    TcpListener::bind(addr).await
}

/// Accept a single connection from a listener.
pub async fn accept(listener: &TcpListener) -> std::io::Result<(TcpStream, SocketAddr)> {
    let (stream, addr) = listener.accept().await?;
    stream.set_nodelay(true)?;
    Ok((stream, addr))
}
