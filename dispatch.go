// Released under MIT License
// Copyright (c) 2020 domosekai

//go:build !linux

package main

func dispatch(total *int) {
	if *httpAddr != "" {
		wg.Add(1)
		go doHTTP(total)
	}
}
