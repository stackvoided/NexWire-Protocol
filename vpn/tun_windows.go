//go:build windows

package main

import (
	"errors"
	"net"
)

type TUN struct {
	name string
	mtu  int
}

func NewTUN(name string, ipCIDR string, mtu int) (*TUN, error) {
	return nil, errors.New("TUN device on Windows requires Wintun.dll driver interface")
}

func (t *TUN) Read(b []byte) (int, error) {
	return 0, errors.New("not implemented")
}

func (t *TUN) Write(b []byte) (int, error) {
	return 0, errors.New("not implemented")
}

func (t *TUN) Close() error {
	return nil
}

func (t *TUN) Name() string {
	return t.name
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
