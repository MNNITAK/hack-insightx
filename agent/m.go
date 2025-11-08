package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

type NetworkEvent struct {
	Hostname  string `json:"hostname"`
	PID       uint32 `json:"pid"`
	Process   string `json:"process"`
	ExePath   string `json:"exe_path"`
	EventType string `json:"event_type"`
	SrcIP     string `json:"src_ip"`
	SrcPort   uint16 `json:"src_port"`
	DstIP     string `json:"dst_ip"`
	DstPort   uint16 `json:"dst_port"`
	Timestamp string `json:"timestamp"`
}

var (
	collectorURL = flag.String("collector", "http://localhost:8080/api/events", "Collector URL")
	mode         = flag.String("mode", "observe", "Mode")
)

func main() {
	flag.Parse()
	
	log.Printf("✅ Network Monitor started (mode: %s)", *mode)
	log.Printf("📡 Sending to: %s", *collectorURL)
	log.Println("🔇 Filtering out localhost traffic")
	
	hostname, _ := os.Hostname()
	
	for {
		cmd := exec.Command("timeout", "2", "tcpdump", "-n", "-l", "-i", "any", 
			"tcp[tcpflags] & (tcp-syn) != 0", "-c", "10")
		output, _ := cmd.CombinedOutput()
		
		lines := strings.Split(string(output), "\n")
		events := []NetworkEvent{}
		
		for _, line := range lines {
			if !strings.Contains(line, " > ") {
				continue
			}
			
			parts := strings.Fields(line)
			if len(parts) < 5 {
				continue
			}
			
			srcFull := ""
			dstFull := ""
			
			for i, part := range parts {
				if part == ">" && i > 0 && i+1 < len(parts) {
					srcFull = parts[i-1]
					dstFull = strings.TrimSuffix(parts[i+1], ":")
					break
				}
			}
			
			if srcFull == "" || dstFull == "" {
				continue
			}
			
			srcIP, srcPort := parseIPPort(srcFull)
			dstIP, dstPort := parseIPPort(dstFull)
			
			// FILTER: Skip localhost/loopback traffic
			if dstIP == "" || dstIP == "0.0.0.0" || 
			   dstIP == "127.0.0.1" || strings.HasPrefix(dstIP, "127.") {
				continue
			}
			
			event := NetworkEvent{
				Hostname:  hostname,
				PID:       0,
				Process:   "tcp",
				ExePath:   "unknown",
				EventType: "CONNECT",
				SrcIP:     srcIP,
				SrcPort:   srcPort,
				DstIP:     dstIP,
				DstPort:   dstPort,
				Timestamp: time.Now().Format(time.RFC3339),
			}
			
			fmt.Printf("🔍 [CONNECT] %s:%d → %s:%d\n",
				event.SrcIP, event.SrcPort, event.DstIP, event.DstPort)
			
			events = append(events, event)
		}
		
		if len(events) > 0 {
			sendEvents(events)
		}
		
		time.Sleep(1 * time.Second)
	}
}

func parseIPPort(s string) (string, uint16) {
	lastDot := strings.LastIndex(s, ".")
	if lastDot == -1 {
		return s, 0
	}
	
	ip := s[:lastDot]
	portStr := s[lastDot+1:]
	
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)
	
	return ip, port
}

func sendEvents(events []NetworkEvent) {
	data, _ := json.Marshal(events)
	resp, err := http.Post(*collectorURL, "application/json", bytes.NewBuffer(data))
	if err != nil {
		// Silently ignore errors (to avoid logging localhost connection errors)
		return
	}
	defer resp.Body.Close()
}