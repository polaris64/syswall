# syswall
A work in progress firewall for Linux syscalls, written in Rust.

## Introduction
`syswall` functions similarly to the *nix `strace` tool, however for each syscall the program blocks the child process's execution and asks the user if the syscall should be allowed or not.  As such, `syswall` can act as a safety barrier between a process and the OS kernel.

`syswall` also collects statistics about the handled syscalls and is able to produce a report after the child process finishes execution.

For more information about what `syswall` does, what is planned, and why, please see [this blog post on my website](https://www.polaris64.net/blog/programming/2019/syswall-a-firewall-for-syscalls)

## Structure
This repository is split as a Cargo workspace into two separate projects: -

  - `lib`: the main `syswall` library containing the main functionality which can be used in other applications as [a Cargo crate](https://crates.io/crates/syswall).
  - `cli`: a simple CLI to the `syswall` library, allowing a single program to be traced similarly to the `strace` tool but with additonal `syswall` functionality.

The project has been split in this way in order to allow for easier integration of other interfaces.  For example, a graphical, web-based or scripting interface could easily be written for the `syswall` library allowing for usage in environments other than the command-line.

## Current progress
`syswall` is a very early prototype and as such only a small amount of the planned functionality is currently implemented.

The handling of syscalls is of course very much platform-dependent.  `syswall` separates the library fuctionality from the actual code to handle particular syscalls, meaning that support for other platforms shold be relatively easy to integrate.  So far however only the Linux x86_64 platform is supported.

From the Linux x86_64 platform, only a relatively small number of syscalls are actively handled at present.  Currently this includes file I/O and some socket syscalls only.

### `strace`
The syswall CLI can be run with the -vv switch causing it to display all syscalls and results.  This provides similar functionality to the `strace` tool, without the interpretation of syscall arguments as yet.

### Interactive execution
For supported syscalls, `syswall` allows the user to perform the following actions: -

 - Allow the syscall once
 - Always allow that particular syscall
 - Block the syscall once (hard or soft)
 - Always block that particular syscall (hard or soft)

When blocking, the program can perform either a "hard" or a "soft" block.  A hard block prevents the syscall from executing and returns an permission denied error to the child process.  A soft block on the other hand prevents the syscall but attempts to return a suitable response to the child process in order to pretend that the syscall was actually executed.

### Saving and loading of a process configuration
The choices made during execution can be saved to a JSON file.  This file can then be loaded during another execution so that the previous choices are used.

This is a work in progress: only always allowed/blocked answers will be saved.

### Reporting
When the child process terminates, `syswall` will output a brief report about the child process's syscalls.  Currently this consists of all files and sockets opened or blocked but will be expanded upon in future versions.

## Future plans
There is a large to-do list for the project, but some of the highlights are: -

 - Allowing more fine-grained choices, such as always allowing a particular syscall with one or more matching arguments
 - Allowing the child process's state (list of files, sockets, etc) to be saved to a file.  This will eventually allow different executions of a program to be compared.
 - Adding an option to ignore all dynamic .so loads.
 - Adding a set of default configurations (e.g. block all sockets but allow file access).
 - Adding of new interfaces, such as graphical, web-based and scripting (Python) interfaces.
