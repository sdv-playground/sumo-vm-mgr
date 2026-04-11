/// Transport abstraction — vsock only.
///
/// Each connection carries the peer CID for identity/policy lookup.

use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;

/// A connection that can be read from and written to.
pub struct Connection {
    reader: Box<dyn Read + Send>,
    writer: Box<dyn Write + Send>,
    /// Peer vsock CID (identity for policy lookup).
    peer_cid: u32,
}

impl Connection {
    pub fn reader(&mut self) -> &mut dyn Read {
        &mut *self.reader
    }

    pub fn writer(&mut self) -> &mut dyn Write {
        &mut *self.writer
    }

    pub fn peer_cid(&self) -> u32 {
        self.peer_cid
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

            let ret = libc::listen(fd, 8);
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

            let peer_cid = addr.svm_cid;

            tracing::info!(
                cid = peer_cid,
                port = self.port,
                "vsock connection accepted"
            );

            let shared = VsockBidi::new(client_fd);
            let reader = Box::new(shared.clone());
            let writer = Box::new(shared);
            Ok(Connection {
                reader,
                writer,
                peer_cid,
            })
        }
    }

    pub fn port(&self) -> u32 {
        self.port
    }
}

/// Shared vsock socket — single fd used for both Read and Write.
/// Clone shares the same underlying fd (via Arc). OwnedFd closes on last drop.
#[derive(Clone)]
struct VsockBidi {
    fd: Arc<OwnedFd>,
}

impl VsockBidi {
    fn new(raw_fd: RawFd) -> Self {
        Self {
            fd: Arc::new(unsafe { OwnedFd::from_raw_fd(raw_fd) }),
        }
    }
}

impl Read for VsockBidi {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }
}

impl Write for VsockBidi {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = unsafe {
            libc::write(
                self.fd.as_raw_fd(),
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
            )
        };
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
