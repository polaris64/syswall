# syswall
A work in progress firewall for Linux syscalls, written in Rust.

## Introduction
syswall functions similarly to the *nix `strace` tool, however for each syscall the program blocks the child process's execution and asks the user if the syscall should be allowed or not.  As such, syswall can act as a safety barrier between a process and the OS kernel.

syswall also collects statistics about the handled syscalls and is able to produce a report after the child process finishes execution.

## Current progress
syswall is a very early prototype and as such only a small amount of the planned functionality is currently implemented.

The handling of syscalls is of course very much platform-dependent.  syswall separates the program fuctionality from the actual code to handle particular syscalls, meaning that support for other platforms shold be relatively easy to integrate.  So far however only the Linux x86_64 platform is supported.

From the Linux x86_64 platform, only a relatively small number of syscalls are actively handled at present.  These consist of open, close, read and write, meaning that currently syswall can manage the child preccess's file handle state only.

### `strace`
syswall can be run with the -vv switch causing it to display all syscalls and results.

### Interactive execution
For supported syscalls, syswall allows the user to perform the following actions: -

 - Allow the syscall once
 - Always allow that particular syscall
 - Block the syscall once (hard or soft)
 - Always block that particular syscall (hard or soft)

When blocking, the program can perform either a "hard" or a "soft" block.  A hard block prevents the syscall from executing and returns an permission denied error to the child process.  A soft block on the other hand prevents the syscall but attempts to return a suitable response to the child process in order to pretend that the syscall was actually executed.

### Saving and loading of a process configuration
The choices made during execution can be saved to a JSON file.  This file can then be loaded during another execution so that the previous choices are used.

This is a work in progress: only always allowed/blocked answers will be saved.

### Reporting
When the child process terminates, syswall will output a brief report about the child process's syscalls.  Currently this consists of all files opened or blocked but will be expanded upon in future versions.

## Future plans
There is a large to-do list for the project, but some of the highlights are: -

 - Allowing more fine-grained choices, such as always allowing a particular syscall with one or more matching arguments
 - Allowing the child process's state (list of files, sockets, etc) to be saved to a file.  This will eventually allow different executions of a program to be compared.
 - Adding an option to ignore all dynamic .so loads.
 - Adding a set of default configurations (e.g. block all sockets but allow file access).
