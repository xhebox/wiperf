//! Concrete transports for the stream tests: TCP, Unix domain sockets, and
//! Linux `AF_VSOCK`.
//!
//! The state machines never name these types; they only see a connect or
//! accept closure, so a host-side SSH forward can replace any of them.

use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;

use completion::{Listener, OwnedSocket, StreamSocket};
use socket2::{Domain, SockAddr, Socket, Type};

use crate::protocol::to_io;
use crate::stream::SocketStream;

/// Resolves `host:port` to every address it names, in resolver order.
///
/// A hostname and an IPv6 literal are both acceptable here; the caller tries
/// each address rather than guessing which family the host meant.
pub fn resolve(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
	let addrs: Vec<SocketAddr> = (host, port).to_socket_addrs()?.collect();
	if addrs.is_empty() {
		return Err(io::Error::new(
			io::ErrorKind::AddrNotAvailable,
			format!("{host}:{port} resolved to no address"),
		));
	}
	Ok(addrs)
}

/// Connects a TCP [`SocketStream`], trying every address `host` resolves to.
pub async fn connect_tcp_any(host: &str, port: u16) -> io::Result<SocketStream> {
	let mut last = None;
	for addr in resolve(host, port)? {
		match connect_tcp(addr).await {
			Ok(stream) => return Ok(stream),
			Err(error) => last = Some(error),
		}
	}
	Err(last.unwrap_or_else(|| io::Error::other("no address to connect to")))
}

/// Connects a TCP [`SocketStream`].
pub async fn connect_tcp(addr: SocketAddr) -> io::Result<SocketStream> {
	let sock = StreamSocket::connect(addr).await.map_err(to_io)?;
	Ok(SocketStream::new(sock))
}

/// Binds a TCP [`Listener`] and returns the address it actually bound.
pub fn bind_tcp(addr: SocketAddr) -> io::Result<(Listener, SocketAddr)> {
	let domain = if addr.is_ipv4() {
		Domain::IPV4
	} else {
		Domain::IPV6
	};
	let socket = Socket::new(domain, Type::STREAM, None)?;
	socket.set_reuse_address(true)?;
	socket.set_nonblocking(true)?;
	socket.bind(&SockAddr::from(addr))?;
	socket.listen(128)?;
	let local = socket.local_addr()?.as_socket().unwrap_or(addr);
	Ok((Listener::new(OwnedSocket::from(socket)), local))
}

/// Connects a Unix domain stream socket at `path`.
pub fn connect_unix(path: &Path) -> io::Result<SocketStream> {
	let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
	socket.connect(&SockAddr::unix(path)?)?;
	socket.set_nonblocking(true)?;
	Ok(SocketStream::new(StreamSocket::new(OwnedSocket::from(
		socket,
	))))
}

/// Binds a Unix domain stream [`Listener`] at `path`.
///
/// An existing file is never removed: binding fails with `EADDRINUSE` instead,
/// because the path may be anything the caller did not create. Removing a
/// stale socket is the caller's decision, not this function's.
pub fn bind_unix(path: &Path) -> io::Result<Listener> {
	let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
	socket.bind(&SockAddr::unix(path)?)?;
	socket.listen(128)?;
	socket.set_nonblocking(true)?;
	Ok(Listener::new(OwnedSocket::from(socket)))
}

/// Binds and listens on a Linux `AF_VSOCK` stream port (`VMADDR_CID_ANY`).
#[cfg(target_os = "linux")]
pub fn bind_vsock(port: u32) -> io::Result<Listener> {
	use std::os::fd::FromRawFd;

	let raw = unsafe {
		libc::socket(
			libc::AF_VSOCK,
			libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
			0,
		)
	};
	if raw < 0 {
		return Err(io::Error::last_os_error());
	}
	let socket = unsafe { Socket::from_raw_fd(raw) };
	bind_vsock_addr(raw, libc::VMADDR_CID_ANY, port)?;
	socket.listen(128)?;
	Ok(Listener::new(OwnedSocket::from(socket)))
}

/// Connects to a Linux `AF_VSOCK` `(cid, port)` stream endpoint.
#[cfg(target_os = "linux")]
pub fn connect_vsock(cid: u32, port: u32) -> io::Result<SocketStream> {
	use std::os::fd::FromRawFd;

	let raw = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
	if raw < 0 {
		return Err(io::Error::last_os_error());
	}
	let socket = unsafe { Socket::from_raw_fd(raw) };
	let addr = vsock_addr(cid, port);
	let ret = unsafe {
		libc::connect(
			raw,
			(&addr as *const libc::sockaddr_vm).cast(),
			size_of::<libc::sockaddr_vm>() as libc::socklen_t,
		)
	};
	if ret < 0 {
		return Err(io::Error::last_os_error());
	}
	socket.set_nonblocking(true)?;
	Ok(SocketStream::new(StreamSocket::new(OwnedSocket::from(
		socket,
	))))
}

#[cfg(target_os = "linux")]
fn vsock_addr(cid: u32, port: u32) -> libc::sockaddr_vm {
	libc::sockaddr_vm {
		svm_family: libc::AF_VSOCK as libc::sa_family_t,
		svm_reserved1: 0,
		svm_port: port,
		svm_cid: cid,
		svm_zero: [0; 4],
	}
}

#[cfg(target_os = "linux")]
fn bind_vsock_addr(raw: libc::c_int, cid: u32, port: u32) -> io::Result<()> {
	let addr = vsock_addr(cid, port);
	let ret = unsafe {
		libc::bind(
			raw,
			(&addr as *const libc::sockaddr_vm).cast(),
			size_of::<libc::sockaddr_vm>() as libc::socklen_t,
		)
	};
	if ret < 0 {
		return Err(io::Error::last_os_error());
	}
	Ok(())
}
