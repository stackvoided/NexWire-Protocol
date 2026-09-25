//go:build linux

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"unsafe"

	"golang.org/x/sys/unix"
)

type TUN struct {
	file *os.File
	name string
	mtu  int
}

type ifreq struct {
	Name  [16]byte
	Flags uint16
	_     [22]byte
}

func NewTUN(name string, ipCIDR string, mtu int) (*TUN, error) {
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("unable to open /dev/net/tun: %w", err)
	}

	var req ifreq
	copy(req.Name[:], name)
	req.Flags = unix.IFF_TUN | unix.IFF_NO_PI

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		file.Fd(),
		uintptr(unix.TUNSETIFF),
		uintptr(unsafe.Pointer(&req)),
	)
	if errno != 0 {
		file.Close()
		return nil, fmt.Errorf("ioctl TUNSETIFF failed with errno %d", errno)
	}

	createdName := cstrToString(req.Name[:])

	if err := sysCmd("ip", "link", "set", "dev", createdName, "mtu", fmt.Sprintf("%d", mtu)); err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to set MTU: %w", err)
	}

	if err := sysCmd("ip", "addr", "add", ipCIDR, "dev", createdName); err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to assign IP address: %w", err)
	}

	if err := sysCmd("ip", "link", "set", "dev", createdName, "up"); err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to set interface up: %w", err)
	}

	return &TUN{
		file: file,
		name: createdName,
		mtu:  mtu,
	}, nil
}

func (t *TUN) Read(b []byte) (int, error) {
	return t.file.Read(b)
}

func (t *TUN) Write(b []byte) (int, error) {
	return t.file.Write(b)
}

func (t *TUN) Close() error {
	_ = sysCmd("ip", "link", "set", "dev", t.name, "down")
	return t.file.Close()
}

func (t *TUN) Name() string {
	return t.name
}

func sysCmd(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("command %s %v failed: %s (err: %w)", name, args, string(out), err)
	}
	return nil
}

func cstrToString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func ExtractIPs(packet []byte) (src net.IP, dst net.IP, ok bool) {
	if len(packet) < 20 {
		return nil, nil, false
	}
	version := packet[0] >> 4
	if version == 4 {
		return net.IP(packet[12:16]), net.IP(packet[16:20]), true
	} else if version == 6 && len(packet) >= 40 {
		return net.IP(packet[8:24]), net.IP(packet[24:40]), true
	}
	return nil, nil, false
}
