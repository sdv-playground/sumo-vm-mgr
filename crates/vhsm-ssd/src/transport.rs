/// Transport abstraction — vsock + TCP.
///
/// vsock is Linux-only (AF_VSOCK). TCP is for dev/test without vsock.
/// QNX can add its own transport implementation later.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

/// A connection that can be read from and written to.
pub struct Connection {
    reader: Box<dyn Read + Send>,
    writer: Box<dyn Write + Send>,
}

impl Connection {
    pub fn reader(&mut self) -> &mut dyn Read {
        &mut *self.reader
    }

    pub fn writer(&mut self) -> &mut dyn Write {
        &mut *self.writer
    }
}

/// Transport listener that accepts connections.
pub enum Transport {
    Vsock(VsockListener),
    Tcp(TcpTransport),
}

impl Transport {
    pub fn accept(&self) -> io::Result<Connection> {
        match self {
            Transport::Vsock(v) => v.accept(),
            Transport::Tcp(t) => t.accept(),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Transport::Vsock(_) => "vsock",
            Transport::Tcp(_) => "tcp",
        }
    }
}

// --- TCP transport ---

pub struct TcpTransport {
    listener: TcpListener,
}

impl TcpTransport {
    pub fn bind(addr: &str) -> io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        Ok(Self { listener })
    }

    pub fn accept(&self) -> io::Result<Connection> {
        let (stream, peer) = self.listener.accept()?;
        tracing::info!("TCP connection from {peer}");
        let reader = Box::new(stream.try_clone()?);
        let writer = Box::new(stream);
        Ok(Connection { reader, writer })
    }
}

// --- vsock transport ---

/// AF_VSOCK constants (from linux/vm_sockets.h).
const AF_VSOCK: i32 = 40;
const VMADDR_CID_ANY: u32 = 0xFFFFFFFF;

#[repr(C)]
struct SockaddrVm {
    svm_family: libc::sa_family_t,
    svm_reserved1: u16,
    svm_port: u32,
    svm_cid: u32,
    svm_flags: u8,
    svm_zero: [u8; 3],
}

pub struct VsockListener {
    fd: OwnedFd,
    port: u32,
}

impl VsockListener {
    pub fn bind(port: u32) -> io::Result<Self> {
        unsafe {
            let fd = libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let owned = OwnedFd::from_raw_fd(fd);

            // Enable SO_REUSEADDR
            let optval: libc::c_int = 1;
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                &optval as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );

            let addr = SockaddrVm {
                svm_family: AF_VSOCK as libc::sa_family_t,
                svm_reserved1: 0,
                svm_port: port,
                svm_cid: VMADDR_CID_ANY,
                svm_flags: 0,
                svm_zero: [0; 3],
            };

            let ret = libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<SockaddrVm>() as libc::socklen_t,
            );
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }

            let ret = libc::listen(fd, 4);
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(Self { fd: owned, port })
        }
    }

    pub fn accept(&self) -> io::Result<Connection> {
        unsafe {
            let mut addr: SockaddrVm = std::mem::zeroed();
            let mut len = std::mem::size_of::<SockaddrVm>() as libc::socklen_t;
            let client_fd = libc::accept(
                self.fd.as_raw_fd(),
                &mut addr as *mut _ as *mut libc::sockaddr,
                &mut len,
            );
            if client_fd < 0 {
                return Err(io::Error::last_os_error());
            }

            tracing::info!(
                cid = addr.svm_cid,
                port = self.port,
                "vsock connection accepted"
            );

            let stream = VsockStream::from_raw_fd(client_fd);
            let reader = Box::new(stream.try_clone()?);
            let writer = Box::new(stream);
            Ok(Connection { reader, writer })
        }
    }
}

/// Wrapper around a vsock socket fd for Read/Write.
struct VsockStream {
    fd: RawFd,
}

impl VsockStream {
    fn from_raw_fd(fd: RawFd) -> Self {
        Self { fd }
    }

    fn try_clone(&self) -> io::Result<Self> {
        let new_fd = unsafe { libc::dup(self.fd) };
        if new_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd: new_fd })
    }
}

impl Read for VsockStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }
}

impl Write for VsockStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = unsafe { libc::write(self.fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for VsockStream {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

/// Convert a TcpStream to a Connection.
impl From<TcpStream> for Connection {
    fn from(stream: TcpStream) -> Self {
        let reader = Box::new(stream.try_clone().unwrap());
        let writer = Box::new(stream);
        Connection { reader, writer }
    }
}
