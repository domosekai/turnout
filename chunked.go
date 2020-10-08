// From Go net/http/internal package
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// The wire protocol for HTTP's "chunked" Transfer-Encoding.

// Package internal contains HTTP internals shared by net/http and
// net/http/httputil.

// Modified by domosekai 2020

package main

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
)

const maxLineLength = 4096 // assumed <= bufio.defaultBufSize

var errLineTooLong = errors.New("header line too long")

// NewChunkedReader returns a new chunkedReader that translates the data read from r
// out of HTTP "chunked" format before returning it.
// The chunkedReader returns io.EOF when the final 0-length chunk is read.
//
// NewChunkedReader is not needed by normal applications. The http package
// automatically decodes chunking when reading response bodies.
func newChunkedReader(r io.Reader) *chunkedReader {
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReader(r)
	}
	return &chunkedReader{r: br}
}

type chunkedReader struct {
	r        *bufio.Reader
	n        uint64 // unread bytes in chunk
	err      error
	buf      [2]byte
	checkEnd bool // whether need to check for \r\n chunk footer
}

func (cr *chunkedReader) beginChunk() []byte {
	// chunk-size CRLF
	var line, line0 []byte
	line, line0, cr.err = readChunkLine(cr.r)
	if cr.err != nil {
		return nil
	}
	cr.n, cr.err = parseHexUint(line)
	if cr.err != nil {
		return nil
	}
	if cr.n == 0 {
		cr.err = io.EOF
	}
	return line0
}

func (cr *chunkedReader) copy(w net.Conn) (number int, n int64, err error) {
	for cr.err == nil {
		h := cr.beginChunk()
		if cr.n > 0 {
			w.Write(h)
			var n0 int64
			n0, cr.err = io.CopyN(w, cr.r, int64(cr.n)+2)
			n += n0 + int64(len(h))
			cr.n = 0
			number++
		}
		if cr.err == io.EOF {
			w.Write(h)
			n += int64(len(h))
			return number, n, cr.err
		}
	}
	return number, n, cr.err
}

func (cr *chunkedReader) copyTo(lo localConn, re remoteConn, addr net.Addr, route int, lastBytes int64) (number int, n int64, err error) {
	for cr.err == nil {
		h := cr.beginChunk()
		if cr.n > 0 {
			lo.conn.Write(h)
			var n0 int64
			r := io.LimitReader(cr.r, int64(cr.n)+2)
			n0, cr.err = re.writeTo(lo, r, true, addr, route, lastBytes+n)
			if errors.Is(cr.err, io.EOF) {
				cr.err = nil
			}
			n += n0 + int64(len(h))
			cr.n = 0
			number++
		}
		if cr.err == io.EOF {
			lo.conn.Write(h)
			n += int64(len(h))
			return number, n, cr.err
		}
	}
	return number, n, cr.err
}

// Read a line of bytes (up to \n) from b.
// Give up if the line exceeds maxLineLength.
// The returned bytes are owned by the bufio.Reader
// so they are only valid until the next bufio read.
func readChunkLine(b *bufio.Reader) (p []byte, p0 []byte, err error) {
	p, err = b.ReadSlice('\n')
	p0 = p
	if err != nil {
		// We always know when EOF is coming.
		// If the caller asked for a line, there should be a line.
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		} else if err == bufio.ErrBufferFull {
			err = errLineTooLong
		}
		return nil, nil, err
	}
	if len(p) >= maxLineLength {
		return nil, nil, errLineTooLong
	}
	p = trimTrailingWhitespace(p)
	p, err = removeChunkExtension(p)
	if err != nil {
		return nil, nil, err
	}
	return
}

func trimTrailingWhitespace(b []byte) []byte {
	for len(b) > 0 && isASCIISpace(b[len(b)-1]) {
		b = b[:len(b)-1]
	}
	return b
}

func isASCIISpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

// removeChunkExtension removes any chunk-extension from p.
// For example,
//     "0" => "0"
//     "0;token" => "0"
//     "0;token=val" => "0"
//     `0;token="quoted string"` => "0"
func removeChunkExtension(p []byte) ([]byte, error) {
	semi := bytes.IndexByte(p, ';')
	if semi == -1 {
		return p, nil
	}
	// TODO: care about exact syntax of chunk extensions? We're
	// ignoring and stripping them anyway. For now just never
	// return an error.
	return p[:semi], nil
}

func parseHexUint(v []byte) (n uint64, err error) {
	for i, b := range v {
		switch {
		case '0' <= b && b <= '9':
			b = b - '0'
		case 'a' <= b && b <= 'f':
			b = b - 'a' + 10
		case 'A' <= b && b <= 'F':
			b = b - 'A' + 10
		default:
			return 0, errors.New("invalid byte in chunk length")
		}
		if i == 16 {
			return 0, errors.New("http chunk length too large")
		}
		n <<= 4
		n |= uint64(b)
	}
	return
}
