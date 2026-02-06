use tokio_vsock::{VsockAddr, VsockListener, VsockStream};

/// Connect to a VSock endpoint.
pub async fn connect(cid: u32, port: u32) -> std::io::Result<VsockStream> {
    VsockStream::connect(VsockAddr::new(cid, port)).await
}

/// Bind a VSock listener.
pub fn listen(port: u32) -> std::io::Result<VsockListener> {
    VsockListener::bind(VsockAddr::new(tokio_vsock::VMADDR_CID_ANY, port))
}

/// Accept a single connection from a VSock listener.
pub async fn accept(listener: &mut VsockListener) -> std::io::Result<(VsockStream, VsockAddr)> {
    listener.accept().await
}
