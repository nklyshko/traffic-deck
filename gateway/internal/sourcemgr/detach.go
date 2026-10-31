package sourcemgr

import "syscall"

// detachedProcAttr is how every child the gateway spawns (capture sources, services,
// module processes) is started: in a new session with no controlling terminal.
//
// Two consequences, both intended:
//
//   - The child cannot write to the terminal. Its stdout/stderr are already redirected to
//     its log, but under one-command mode the terminal belongs to the TUI, and a child (or a
//     grandchild it spawns — dumpcap, a browser) that opens /dev/tty directly would scribble
//     over the viewer. With no controlling terminal, /dev/tty cannot be opened.
//   - The child is detached from the terminal's signals. A Ctrl-C or a terminal hangup no
//     longer reaches it, so the gateway must reap it itself: the session leader's pid is
//     also its process-group id, so a group-kill of -pid takes the child and everything it
//     started. This is why the gateway handles SIGINT/SIGTERM/SIGHUP and tears down rather
//     than dying where it stands (see cmd/gateway shutdownSignals).
func detachedProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}
