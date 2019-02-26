use nix::errno::Errno;
use nix::fcntl::OFlag;
use nix::sys::socket;

#[derive(Debug, PartialEq)]
pub enum ProcessFileState {
    Closed,
    CouldNotOpen(Errno),
    OpenBlockedHard,
    OpenBlockedSoft,
    Opened(usize),
    PendingSyscall,
}

#[derive(Debug)]
pub struct ProcessFileRec {
    pub state: ProcessFileState,
    pub filename: String,
    pub mode: Option<OFlag>,
    pub flags: Option<OFlag>,
}

impl ProcessFileRec {
    pub fn new(path: &str, flag_bits: isize, mode_bits: isize) -> Self {
        Self {
            state: ProcessFileState::PendingSyscall,
            filename: String::from(path),
            mode: OFlag::from_bits(mode_bits as libc::c_int),
            flags: OFlag::from_bits(flag_bits as libc::c_int),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum ProcessSocketState {
    Closed,
    CouldNotCreate(Errno),
    CreateBlockedHard,
    CreateBlockedSoft,
    Created(usize),
    PendingSyscall,
}

#[derive(Debug)]
pub enum SocketConnectionState {
    Connected,
    ConnectBlockedHard,
    ConnectBlockedSoft,
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

#[derive(Debug)]
pub struct ProcessState {
    files: Vec<ProcessFileRec>,
    sockets: Vec<ProcessSocketRec>,
}

impl ProcessState {
    pub fn new() -> Self {
        Self {
            files: Vec::new(),
            sockets: Vec::new(),
        }
    }

    pub fn file_by_fd(&mut self, fd: usize) -> Option<&mut ProcessFileRec> {
        self.files
            .iter_mut()
            .find(|x| x.state == ProcessFileState::Opened(fd))
    }

    pub fn socket_by_fd(&mut self, fd: usize) -> Option<&mut ProcessSocketRec> {
        self.sockets
            .iter_mut()
            .find(|x| x.state == ProcessSocketState::Created(fd))
    }

    pub fn file_by_path(&mut self, path: &str) -> Option<&mut ProcessFileRec> {
        self.files.iter_mut().find(|x| x.filename == path)
    }

    pub fn add_pending_file(&mut self, path: &str, flags: isize, mode: isize) {
        if self.file_by_path(path).is_none() {
            self.files.push(ProcessFileRec::new(path, flags, mode));
        }
    }

    pub fn add_pending_socket(&mut self, af: isize, sock_type: isize, sock_proto: isize) {
        let v = ProcessSocketRec::new(af, sock_type, sock_proto);
        self.sockets.push(v);
    }

    pub fn first_pending_file(&mut self) -> Option<&mut ProcessFileRec> {
        self.files
            .iter_mut()
            .find(|x| x.state == ProcessFileState::PendingSyscall)
    }

    pub fn first_pending_socket(&mut self) -> Option<&mut ProcessSocketRec> {
        self.sockets
            .iter_mut()
            .find(|x| x.state == ProcessSocketState::PendingSyscall)
    }

    pub fn update_pending_file_state(&mut self, file_state: ProcessFileState) {
        if let Some(f) = self.first_pending_file() {
            f.state = file_state;
        }
    }

    pub fn update_pending_socket_state(&mut self, sock_state: ProcessSocketState) {
        if let Some(s) = self.first_pending_socket() {
            s.state = sock_state;
        }
    }

    pub fn update_file_state_by_fd(&mut self, fd: usize, state: ProcessFileState) {
        if let Some(f) = self.file_by_fd(fd) {
            f.state = state;
        }
    }

    pub fn update_socket_state_by_fd(&mut self, fd: usize, state: ProcessSocketState) {
        if let Some(f) = self.socket_by_fd(fd) {
            f.state = state;
        }
    }

    pub fn report_blocked_files(&self, join: &str, prefix: &str) -> String {
        self.files
            .iter()
            .filter(|x| match x.state {
                ProcessFileState::OpenBlockedHard | ProcessFileState::OpenBlockedSoft => true,
                _ => false,
            })
            .map(|x| String::from(prefix) + &x.filename.clone())
            .collect::<Vec<String>>()
            .as_slice()
            .join(join)
    }

    pub fn report_opened_files(&self, join: &str, prefix: &str) -> String {
        self.files
            .iter()
            .filter(|x| match x.state {
                ProcessFileState::Opened(_) | ProcessFileState::Closed => true,
                _ => false,
            })
            .map(|x| String::from(prefix) + &x.filename.clone())
            .collect::<Vec<String>>()
            .as_slice()
            .join(join)
    }

    pub fn report_sockets(&self, join: &str, prefix: &str) -> String {
        self.sockets
            .iter()
            .filter(|x| match x.state {
                ProcessSocketState::Created(_) | ProcessSocketState::Closed => true,
                _ => false,
            })
            .map(|x| String::from(prefix) + &format!("{:?}", &x.address))
            .collect::<Vec<String>>()
            .as_slice()
            .join(join)
    }

    pub fn report(&self) -> String {
        let blocked_files = self.report_blocked_files("\n", "  - ");
        let opened_files = self.report_opened_files("\n", "  - ");
        let sockets = self.report_sockets("\n", "  - ");
        let mut res = String::new();
        if !blocked_files.is_empty() {
            res += &format!(
                "\nThe process was blocked from opening the following files: -\n{}",
                blocked_files
            );
        }
        if !opened_files.is_empty() {
            res += &format!(
                "\nThe process opened the following files: -\n{}",
                opened_files
            );
        }
        if !sockets.is_empty() {
            res += &format!(
                "\nThe process created the following sockets: -\n{}",
                sockets
            );
        }
        res
    }
}
