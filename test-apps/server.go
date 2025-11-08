// Simple TCP server for testing
package main

import (
	"fmt"
	"log"
	"net"
)

func main() {
	listener, err := net.Listen("tcp", ":9999")
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	fmt.Println("🎧 Test server listening on :9999")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}

		fmt.Printf("✅ Connection from: %s\n", conn.RemoteAddr())
		
		go func(c net.Conn) {
			defer c.Close()
			buf := make([]byte, 1024)
			for {
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				fmt.Printf("📨 Received: %s", buf[:n])
				c.Write([]byte("Echo: "))
				c.Write(buf[:n])
			}
		}(conn)
	}
}