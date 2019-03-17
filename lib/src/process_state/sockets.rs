use nix::errno::Errno;
use nix::sys::socket;
use std::fmt;

#[derive(Debug, PartialEq)]
pub enum ProcessSocketState {
    Closed,
    CouldNotCreate(Errno),
    CreateBlockedHard,
    CreateBlockedSoft,
    Created(usize),
    PendingSyscall,
}

impl fmt::Display for ProcessSocketState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ProcessSocketState::Created(fd) => {
                write!(f, "open with FD {}", fd)
            },
            ProcessSocketState::Closed => {
                write!(f, "closed")
            },
            ProcessSocketState::CouldNotCreate(errno) => {
                write!(f, "creation error: {:?}", errno)
            },
            _ => {
                write!(f, "unknown state")
            }
        }
    }
}

#[derive(Debug)]
pub enum SocketConnectionState {
    Connected,
    ConnectBlockedHard,
    ConnectBlockedSoft,
    ConnectError(Errno),
    Disconnected,
}

#[derive(Debug)]
pub enum SocketType {
    Datagram,
    Raw,
    RDM,
    SeqPacket,
    Stream,
}

impl SocketType {
    pub fn from_i32(x: i32) -> Option<SocketType> {

        // Socket flags are combined with the type i32 (bitwise OR), so only match on the non-flag
        // bits. See socket(2) manpage for details.
        match x & (!libc::SOCK_NONBLOCK) & (!libc::SOCK_CLOEXEC) {
            libc::SOCK_DGRAM => Some(SocketType::Datagram),
            libc::SOCK_RAW => Some(SocketType::Raw),
            libc::SOCK_RDM => Some(SocketType::RDM),
            libc::SOCK_SEQPACKET => Some(SocketType::SeqPacket),
            libc::SOCK_STREAM => Some(SocketType::Stream),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum SocketProtocol {
    IP,
    TCP,
    UDP,
}

impl SocketProtocol {
    pub fn from_i32(x: i32) -> Option<SocketProtocol> {
        match x {
            libc::IPPROTO_IP => Some(SocketProtocol::IP),
            libc::IPPROTO_TCP => Some(SocketProtocol::TCP),
            libc::IPPROTO_UDP => Some(SocketProtocol::UDP),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct ProcessSocketRec {
    pub address: Option<socket::SockAddr>,
    pub connection_state: SocketConnectionState,
    pub sock_af: Option<socket::AddressFamily>,
    pub sock_flags: socket::SockFlag,
    pub sock_proto: Option<SocketProtocol>,
    pub sock_type: Option<SocketType>,
    pub state: ProcessSocketState,
}

impl ProcessSocketRec {
    pub fn new(af_bits: isize, type_bits: isize, proto_bits: isize) -> Self {
        Self {
            address: None,
            connection_state: SocketConnectionState::Disconnected,
            sock_af: socket::AddressFamily::from_i32(af_bits as i32),
            sock_flags: socket::SockFlag::from_bits_truncate(type_bits as libc::c_int),
            sock_proto: SocketProtocol::from_i32(proto_bits as i32),
            sock_type: SocketType::from_i32(type_bits as i32),
            state: ProcessSocketState::PendingSyscall,
        }
    }
}

impl fmt::Display for ProcessSocketRec {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.state {
            ProcessSocketState::Created(_) | ProcessSocketState::Closed => {
                write!(
                    f,
                    "Socket: {} ({:?}, {}, {:?}, {}, {}), address: {}",
                    self.state,
                    self.connection_state,
                    match &self.sock_af {
                        Some(v) => format!("{:?}", &v),
                        None => String::from("No address family"),
                    },
                    self.sock_flags,
                    match &self.sock_proto {
                        Some(v) => format!("{:?}", &v),
                        None => String::from("No protocol"),
                    },
                    match &self.sock_type {
                        Some(v) => format!("{:?}", &v),
                        None => String::from("No socket type"),
                    },
                    match self.address {
                        Some(v) => format!("{:?}", &v),
                        None => String::from("Not bound to an address"),
                    },
                )
            },
            _ => write!(f, "Socket: {}", self.state)
        }
    }
}
