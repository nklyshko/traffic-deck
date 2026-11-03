//go:build windows

package main

import "os/exec"

// A console Ctrl-C reaches only console processes; Wireshark is a GUI one already.
func detach(*exec.Cmd) {}
