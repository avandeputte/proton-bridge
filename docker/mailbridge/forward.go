package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// A handler serves one connection from a mail client.
type handler func(ctx context.Context, conn net.Conn)

// listen accepts connections on addr and hands each to handle, until the
// listener it returns is closed or ctx is cancelled.
func listen(ctx context.Context, wg *sync.WaitGroup, name, addr string, handle handler) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		_ = ln.Close()
	}()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
					return
				}
				log.Printf("%s accept failed: %v", name, err)
				time.Sleep(200 * time.Millisecond)
				continue
			}
			go handle(ctx, conn)
		}
	}()
	return ln, nil
}

// forwarder pipes connections to the address returned by target. Bridge binds
// its IMAP and SMTP servers to 127.0.0.1 only, so this is what makes them
// reachable from the LAN. The bytes are passed through untouched: STARTTLS/TLS
// is still negotiated end-to-end with the target.
//
// With proxyHeader, a PROXY protocol v1 line is sent first so the target (Dovecot)
// knows the real client address for its logs and brute-force throttling.
func forwarder(name string, target func() string, proxyHeader bool) handler {
	return func(ctx context.Context, conn net.Conn) { forward(ctx, name, conn, target(), proxyHeader) }
}

// startForwarder forwards the connections arriving on addr.
func startForwarder(ctx context.Context, wg *sync.WaitGroup, name, addr string, target func() string, proxyHeader bool) {
	ln, err := listen(ctx, wg, name, addr, forwarder(name, target, proxyHeader))
	if err != nil {
		log.Fatalf("cannot listen for %s on %s: %v", name, addr, err)
	}
	log.Printf("forwarding %s: %s -> %s", name, ln.Addr(), target())
}

// proxyLine builds the PROXY protocol v1 header describing a client connection.
func proxyLine(client net.Conn) string {
	src, ok1 := client.RemoteAddr().(*net.TCPAddr)
	dst, ok2 := client.LocalAddr().(*net.TCPAddr)
	if !ok1 || !ok2 {
		return "PROXY UNKNOWN\r\n"
	}
	if s4, d4 := src.IP.To4(), dst.IP.To4(); s4 != nil && d4 != nil {
		return fmt.Sprintf("PROXY TCP4 %s %s %d %d\r\n", s4, d4, src.Port, dst.Port)
	}
	return fmt.Sprintf("PROXY TCP6 %s %s %d %d\r\n", src.IP.To16(), dst.IP.To16(), src.Port, dst.Port)
}

func forward(ctx context.Context, name string, client net.Conn, target string, proxyHeader bool) {
	defer func() { _ = client.Close() }()

	dialer := net.Dialer{Timeout: 5 * time.Second}
	upstream, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		hint := "bridge only does once an account is signed in"
		if proxyHeader {
			hint = "Dovecot is still starting"
		}
		log.Printf("%s: connection from %s refused, nothing is listening on %s (%s): %v",
			name, client.RemoteAddr(), target, hint, err)
		return
	}
	defer func() { _ = upstream.Close() }()

	if proxyHeader {
		if _, err := io.WriteString(upstream, proxyLine(client)); err != nil {
			return
		}
	}

	stop := context.AfterFunc(ctx, func() {
		_ = client.Close()
		_ = upstream.Close()
	})
	defer stop()

	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if tcp, ok := dst.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		done <- struct{}{}
	}
	go pipe(upstream, client)
	go pipe(client, upstream)

	<-done
	// Give the other direction a moment to flush, then tear everything down.
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
}
