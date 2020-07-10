// Written and released by missdear under MIT License
// Downloaded from https://github.com/missdeer/avege/blob/master/inbound/redir/redir_iptables.go

// Modified by domosekai 2020

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
)

const (
	SO_ORIGINAL_DST      = 80 // from linux/include/uapi/linux/netfilter_ipv4.h
	IP6T_SO_ORIGINAL_DST = 80 // from linux/include/uapi/linux/netfilter_ipv6/ip6_tables.h
)

// Call getorigdst() from linux/net/ipv4/netfilter/nf_conntrack_l3proto_ipv4.c
func getorigdst(fd uintptr) (rawaddr []byte, err error) {
	// IPv4 address starts at the 5th byte, 4 bytes long (206 190 36 45)
	addr, err := syscall.GetsockoptIPv6Mreq(int(fd), syscall.IPPROTO_IP, SO_ORIGINAL_DST)
	if err != nil {
		return nil, err
	}

	rawaddr = make([]byte, 1+net.IPv4len+2)
	// address type, 1 - IPv4, 4 - IPv6, 3 - hostname
	rawaddr[0] = 1
	// raw IP address, 4 bytes for IPv4 or 16 bytes for IPv6
	copy(rawaddr[1:], addr.Multiaddr[4:4+net.IPv4len])
	// port
	copy(rawaddr[1+net.IPv4len:], addr.Multiaddr[2:2+2])

	return rawaddr, nil
}

// Call ipv6_getorigdst() from linux/net/ipv6/netfilter/nf_conntrack_l3proto_ipv6.c
// NOTE: I haven't tried yet but it should work since Linux 3.8.
func ipv6_getorigdst(fd uintptr) (addr []byte, err error) {
	mtuinfo, err := syscall.GetsockoptIPv6MTUInfo(int(fd), syscall.IPPROTO_IPV6, IP6T_SO_ORIGINAL_DST)
	if err != nil {
		return nil, err
	}
	raw := mtuinfo.Addr

	addr = make([]byte, 1+net.IPv6len+2)
	addr[0] = 4
	copy(addr[1:1+net.IPv6len], raw.Addr[:])
	binary.LittleEndian.PutUint16(addr[1+net.IPv6len:], raw.Port)
	return addr, nil
}

// Get the original destination of a TCP connection.
func getOriginalDst(c *net.TCPConn) (host string, err error) {
	//newTCPConn = c
	f, err := c.File()
	if err != nil {
		return
	}
	defer f.Close()

	fd := f.Fd()

	// The File() call above puts both the original socket fd and the file fd in blocking mode.
	// Set the file fd back to non-blocking mode and the original socket fd will become non-blocking as well.
	// Otherwise blocking I/O will waste OS threads.
	if err = syscall.SetNonblock(int(fd), true); err != nil {
		return
	}
	rawaddr, err := ipv6_getorigdst(fd)
	if err == nil {
		ip := net.IP(rawaddr[1 : 1+net.IPv6len])
		host = fmt.Sprintf("[%s]:%d",
			ip.To16().String(),
			uint16(rawaddr[1+net.IPv6len])<<8+uint16(rawaddr[1+net.IPv6len+1]))
		return
	}

	rawaddr, err = getorigdst(fd)
	if err == nil {
		host = fmt.Sprintf("%d.%d.%d.%d:%d",
			rawaddr[1],
			rawaddr[2],
			rawaddr[3],
			rawaddr[4],
			uint16(rawaddr[1+net.IPv4len])<<8+uint16(rawaddr[1+net.IPv4len+1]))
		return
	}

	return
}
