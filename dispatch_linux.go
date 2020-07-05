// Released under MIT License
// Copyright (c) 2020 domosekai

package main

func dispatch(total *int) {
	if *tranAddr != "" {
		wg.Add(1)
		go doTransparent(total)
	}
	if *httpAddr != "" {
		wg.Add(1)
		go doHTTP(total)
	}
}
