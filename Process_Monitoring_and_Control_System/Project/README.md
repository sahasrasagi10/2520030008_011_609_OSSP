# LINUX PROCESS MANAGEMENT SYSTEM

A Linux/POSIX user-space C project demonstrating process management, IPC, signals, FCFS scheduling, memory monitoring, Linux file I/O, and POSIX thread synchronization.

## Build

Run in Ubuntu/WSL:

```bash
make
./osmanager
```

## Commands

```text
create
status
stop
resume
terminate

create-file
search <file> <keyword>
delete-file <file>
file-info <file>
memory

queue
run
result

execute <command>
help
clear
exit
```

## Implementation coverage

### CO1
- Shell-like user-space command interface
- Linux/POSIX system calls
- `fork()`, `execvp()`, `waitpid()`
- Command execution flow

### CO2
- Parent/worker process creation
- PID/PPID and process states through `/proc`
- Process lifecycle and termination
- `SIGSTOP`, `SIGCONT`, `SIGTERM`
- FCFS user-level task scheduling
- Process groups/session identifiers shown by `status`

### CO3
- Two anonymous pipes for parent/worker IPC
- Named FIFO created and used internally during worker startup
- POSIX signal handling in the worker
- Process-group setup with `setpgid()` and session information through `getsid()`

### CO4
- Virtual and resident memory from `/proc`
- Page size and page counts
- Minor/major page faults
- Dynamic allocation with `malloc()`/`free()`
- Copy-on-Write demonstration using `fork()`
- Process memory monitoring

### CO5
- File creation/search/deletion
- File descriptors and `open/read/write/close/unlink`
- Inode, permissions, size, links using `stat()`
- Buffered and unbuffered file I/O
- Memory-mapped file access using `mmap()`/`munmap()`
- Filesystem type information

### CO6
- POSIX threads inside the worker process
- Shared task buffer
- Mutex protection
- Condition-variable coordination
- Counting semaphore
- Thread cancellation/join and synchronized cleanup

The terminal intentionally keeps these implementation details mostly hidden so the project remains easy to demonstrate and explain.
