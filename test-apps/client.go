package main

import (
	"fmt"
	"log"
	"net"
	"time"
)

func main() {
	fmt.Println("📞 Connecting to test server...")

	conn, err := net.Dial("tcp", "localhost:9999")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	fmt.Println("✅ Connected!")

	// Send test messages
	for i := 1; i <= 5; i++ {
		msg := fmt.Sprintf("Test message %d\n", i)
		conn.Write([]byte(msg))
		fmt.Printf("📤 Sent: %s", msg)
		
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		fmt.Printf("📥 Received: %s", buf[:n])
		
		time.Sleep(2 * time.Second)
	}
}