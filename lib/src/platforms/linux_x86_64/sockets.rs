use log::{error, info};
use nix::sys::socket;
use nix::unistd::Pid;
use std::ptr;

use crate::child_process::{self, ChildProcessBuffer};
use crate::process_state::ProcessState;
use crate::process_state::sockets::{SocketProtocol, SocketType};
use crate::syscalls::SyscallRegs;

impl Into<Option<socket::SockAddr>> for ChildProcessBuffer {
    fn into(self) -> Option<socket::SockAddr> {

        // First interpret buffer as sockaddr in order to get sa_family and generic sa_data
        #[allow(clippy::cast_ptr_alignment)]
        let sockaddr: libc::sockaddr = unsafe { ptr::read_unaligned(self.0.as_ptr() as *const libc::sockaddr) };

        match libc::c_int::from(sockaddr.sa_family) {
            libc::AF_INET => Some(
                // sa_data contains necessary additional fields
                socket::SockAddr::new_inet(
                    socket::InetAddr::new(

                        // Extract IPv4 address bytes from sa_data
                        socket::IpAddr::new_v4(
                            sockaddr.sa_data[2] as u8,
                            sockaddr.sa_data[3] as u8,
                            sockaddr.sa_data[4] as u8,
                            sockaddr.sa_data[5] as u8,
                        ),

                        // Extract 16-bit port from sa_data (big-endian)
                        ((sockaddr.sa_data[0] as u16) << 8) | (sockaddr.sa_data[1] as u16),
                    ),
                ),
            ),
            libc::AF_UNIX => {
                // Interpret buffer as sockaddr_un
                #[allow(clippy::cast_ptr_alignment)]
                let sockaddr: libc::sockaddr_un = unsafe { ptr::read_unaligned(self.0.as_ptr() as *const libc::sockaddr_un) };

                match socket::SockAddr::new_unix(

                    // Collect sun_path as Vec<u8> while element is non-zero. sun_path can be a
                    // maximum of 108 characters and is null-terminated if smaller.
                    sockaddr.sun_path
                        .iter()
                        .map(|x| *x as u8)
                        .take_while(|x| *x != 0)
                        .collect::<Vec<u8>>()
                        .as_slice()
                ) {
                    Ok(x) => Some(x),
                    Err(_) => None,
                }
            }

            // TODO: decode other sa_family types: AF_INET6, AF_NETLINK
            _ => None,
        }
    }
}

pub fn handle_connect_pre(
    state: &mut ProcessState,
    regs: &SyscallRegs,
    pid: Pid,
) {
    info!("Child process {} wants to connect socket {}", pid, regs.rdi);
    match child_process::get_child_buffer(pid, regs.rsi as usize, regs.rdx as usize) {
        Ok(buf) => {
            let sockaddr: Option<socket::SockAddr> = buf.into();
            info!(" - Socket address: {:?}", sockaddr);

            // Update socket's address in state
            if let Some(ref mut sock) = state.socket_by_fd(regs.rdi as usize) {
                sock.address = sockaddr;
            }
        },
        Err(e) => error!(" - Unable to read from child process buffer: {}", e),
    };
}

pub fn handle_socket_pre(
    state: &mut ProcessState,
    regs: &SyscallRegs,
    pid: Pid,
) {
    info!(
        "Child process {} wants to create a socket (family: {:?}, type: {:?}, protocol: {:?})",
        pid,
        socket::AddressFamily::from_i32(regs.rdi as libc::c_int),
        SocketType::from_i32(regs.rsi as libc::c_int),
        SocketProtocol::from_i32(regs.rdx as libc::c_int),
    );
    state.add_pending_socket(regs.rdi as isize, regs.rsi as isize, regs.rdx as isize);
}
