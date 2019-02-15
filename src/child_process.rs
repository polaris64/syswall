use std::ffi::CString;
use nix::unistd;
use nix::sys::ptrace;
use nix::sys::uio;
use nix::sys::wait;

use crate::process_conf::ProcessConf;
use crate::process_state::{ProcessState};
use crate::syscalls;

pub fn get_child_buffer(pid: unistd::Pid, base: usize, len: usize) -> Result<String, &'static str> {
    let mut rbuf: Vec<u8> = vec![0; len];
    let remote_iovec = uio::RemoteIoVec{ base, len };
    uio::process_vm_readv(
        pid,
        &[uio::IoVec::from_mut_slice(rbuf.as_mut_slice())],
        &[remote_iovec],
    )
        .map_err(|_| "Unable to read from child process virtual memory")?;
    Ok(String::from_utf8_lossy(&rbuf).into_owned())
}

pub fn get_child_buffer_cstr(pid: unistd::Pid, base: usize) -> Result<String, &'static str> {
    let mut final_buf: Vec<u8> = Vec::with_capacity(255);

    // Current RemoteIoVec base address
    let mut current_base = base;

    // Index of 0 byte in final_buf
    let mut nul_idx: isize= -1;

    // Keep reading 255-byte chunks from the process VM until one contains a 0 byte
    // (null-termination character)
    loop {

        // Read into a temporary buffer
        let mut rbuf: Vec<u8> = vec![0; 255];
        let remote_iovec = uio::RemoteIoVec{ base: current_base, len: 255 };
        uio::process_vm_readv(
            pid,
            &[uio::IoVec::from_mut_slice(rbuf.as_mut_slice())],
            &[remote_iovec],
        )
            .map_err(|_| "Unable to read from child process virtual memory")?;

        // Append temporary buffer to the final buffer and increase base address pointer
        final_buf.append(&mut rbuf);
        current_base += 255;

        // If final_buf contains a 0 byte, store the index and break from the read loop
        if final_buf.contains(&0) {
            if let Some(idx) = final_buf.iter().position(|&x| x == 0) {
                nul_idx = idx as isize;
            }
            break;
        }
    }
    if nul_idx > -1 {
        Ok(String::from_utf8_lossy(&final_buf[0..(nul_idx as usize)]).into_owned())
    } else {
        Err("Null-terminated string not found")
    }
}

pub fn exec_child(cmd: Vec<&str>) -> Result<(), String> {
    ptrace::traceme().map_err(|_| "CHILD: could not enable tracing by parent (PTRACE_TRACEME failed)")?;

    // Extract child command (first arg)
    let child_cmd = CString::new(
        *cmd.first().ok_or("Unable to extract tracee command")?
    )
        .map_err(|_| "Unable to extract tracee command")?;

    // Extract child arguments (including first command)
    let child_args = cmd
        .iter()
        .map(|v| CString::new(*v).unwrap_or_default())
        .collect::<Vec<CString>>();

    eprintln!("CHILD: executing {:?} with argv {:?}...", child_cmd, child_args);
    unistd::execvp(&child_cmd, &child_args)
        .map_err(|_| format!("unable to execute {:?}", child_cmd))?;
    Ok(())
}

pub fn wait_child(pid: unistd::Pid) -> Result<nix::sys::wait::WaitStatus, String> {
    wait::waitpid(pid, None).map_err(|_| format!("Unable to wait for child PID {}", pid))
}

pub fn child_loop(child: unistd::Pid, conf: &mut ProcessConf) -> Result<ProcessState, String> {
    let mut state = ProcessState::new();

    loop {
        // Await next child syscall
        if ptrace::syscall(child).is_err() {
            eprintln!("Unable to ask for next child syscall");
            break;
        };
        wait_child(child)?;

        // Get syscall details
        match ptrace::getregs(child) {
            Ok(mut regs) => {
                let syscall_id = regs.orig_rax;

                let handler_res = syscalls::handle_pre_syscall(conf, &mut state, child, syscall_id, &mut regs);

                // Execute this child syscall
                ptrace::syscall(child).map_err(|_| "Unable to execute current child syscall")?;
                wait_child(child)?;

                // Get syscall result
                match ptrace::getregs(child) {
                    Ok(ref mut regs) => {
                        syscalls::handle_post_syscall(handler_res, &mut state, child, syscall_id, regs);
                    },
                    Err(err) => {
                        if err.as_errno() == Some(nix::errno::Errno::ESRCH) {
                            eprintln!("\nChild process terminated");
                            break;
                        }
                        eprintln!("Unable to get syscall registers after servicing");
                    },
                };
            },
            Err(err) => {
                eprintln!("Unable to get syscall registers before servicing");
                if err.as_errno() == Some(nix::errno::Errno::ESRCH) {
                    eprintln!("\nChild process terminated");
                    break;
                }
            },
        };
    }

    Ok(state)
}
