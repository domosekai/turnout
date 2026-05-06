// Released under MIT License
// Copyright (c) 2020 domosekai

// SOCKS5 proxy

package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

func PerformHandshake(conn net.Conn) error {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}

	if buf[0] != 0x05 {
		return fmt.Errorf("unsupported SOCKS version: %v", buf[0])
	}

	numMethods := buf[1]
	methods := make([]byte, numMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	_, err := conn.Write([]byte{0x05, 0x00})
	return err
}

func ReadRequest(conn net.Conn) (string, string, error) {
	// Read request header
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return "", "", err
	}

	if buf[0] != 0x05 {
		return "", "", fmt.Errorf("unsupported SOCKS version: %v", buf[0])
	}

	cmd := buf[1] // Command (0x01 = CONNECT)
	if cmd != 0x01 {
		return "", "", fmt.Errorf("unsupported command: %v", cmd)
	}

	// Address type
	atyp := buf[3]
	var host string
	switch atyp {
	case 0x01: // IPv4
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", "", err
		}
		host = net.IP(ip).String()
	case 0x03: // Domain name
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return "", "", err
		}
		if length[0] == 0 {
			return "", "", fmt.Errorf("domain name length %v is invalid", length[0])
		}
		domain := make([]byte, length[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", "", err
		}
		host = string(domain)
	case 0x04: // IPv6
		ip := make([]byte, 16)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", "", err
		}
		host = net.IP(ip).String()
	default:
		return "", "", fmt.Errorf("unsupported address type %v", atyp)
	}

	// Read port
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", "", err
	}
	port := binary.BigEndian.Uint16(portBuf)

	return host, fmt.Sprintf("%d", port), nil
}

func ReplySuccess(conn net.Conn) {
	// Reply with success
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

func ReplyFailure(conn net.Conn) {
	// Reply with failure
	conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}
