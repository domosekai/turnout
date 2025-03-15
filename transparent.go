// Released under MIT License
// Copyright (c) 2020 domosekai

//go:build !linux

package main

import "syscall"

func transparentControl(network, address string, c syscall.RawConn) error {
	return nil
}
