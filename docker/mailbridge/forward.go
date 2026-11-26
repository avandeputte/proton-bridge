package main

import (
	"context"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// startForwarder accepts connections on addr and pipes them to the address
// returned by target. Bridge binds its IMAP and SMTP servers to 127.0.0.1 only,
// so this is what makes them reachable from the LAN. The bytes are passed
// through untouched: STARTTLS/TLS is still negotiated end-to-end with bridge.
func startForwarder(ctx context.Context, wg *sync.WaitGroup, name, addr string, target func() string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("cannot listen for %s on %s: %v", name, addr, err)
	}
	log.Printf("forwarding %s: %s -> bridge", name, ln.Addr())

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
				if ctx.Err() != nil {
					return
				}
				log.Printf("%s accept failed: %v", name, err)
				time.Sleep(200 * time.Millisecond)
				continue
			}
			go forward(ctx, name, conn, target())
		}
	}()
}

func forward(ctx context.Context, name string, client net.Conn, target string) {
	defer func() { _ = client.Close() }()

	dialer := net.Dialer{Timeout: 5 * time.Second}
	upstream, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		log.Printf("%s: connection from %s refused, bridge is not listening on %s (it only does once an account is signed in): %v",
			name, client.RemoteAddr(), target, err)
		return
	}
	defer func() { _ = upstream.Close() }()

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
