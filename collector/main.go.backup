package main

import (
	"database/sql"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
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

type Rule struct {
	ID        int    `json:"id"`
	Process   string `json:"process"`
	DstIP     string `json:"dst_ip"`
	DstPort   uint16 `json:"dst_port"`
	Action    string `json:"action"`
	CreatedAt string `json:"created_at"`
}

type Config struct {
	Mode string `json:"mode"`
}

var (
	db         *sql.DB
	config     Config
	configLock sync.RWMutex
)

func main() {
	var err error
	db, err = sql.Open("sqlite3", "./events.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	initDB()
	loadConfig()

	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	r.POST("/api/events", handleEvents)
	r.GET("/api/events", getEvents)
	r.GET("/api/rules", getRules)
	r.POST("/api/rules", addRule)
	r.DELETE("/api/rules/:id", deleteRule)
	r.GET("/api/config", getConfig)
	r.POST("/api/config", updateConfig)
	r.GET("/api/stats", getStats)

	log.Println("🚀 Collector started on :8080")
	log.Printf("📊 Mode: %s", config.Mode)
	r.Run(":8080")
}

func initDB() {
	schema := `
	CREATE TABLE IF NOT EXISTS events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		hostname TEXT,
		pid INTEGER,
		process TEXT,
		exe_path TEXT,
		event_type TEXT,
		src_ip TEXT,
		src_port INTEGER,
		dst_ip TEXT,
		dst_port INTEGER,
		status TEXT,
		timestamp DATETIME
	);

	CREATE TABLE IF NOT EXISTS rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		process TEXT,
		dst_ip TEXT,
		dst_port INTEGER,
		action TEXT,
		created_at DATETIME
	);

	CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp);
	CREATE INDEX IF NOT EXISTS idx_process ON events(process);
	`

	_, err := db.Exec(schema)
	if err != nil {
		log.Fatal("Failed to create schema:", err)
	}

	db.Exec(`INSERT OR IGNORE INTO rules (id, process, dst_ip, dst_port, action, created_at) 
			  VALUES (1, '*', '127.0.0.1', 0, 'allow', datetime('now'))`)
}

func loadConfig() {
	config.Mode = "observe"
	if data, err := os.ReadFile("../config.yaml"); err == nil {
		if strings.Contains(string(data), "enforce") {
			config.Mode = "enforce"
		}
	}
}

func handleEvents(c *gin.Context) {
	var events []NetworkEvent
	if err := c.BindJSON(&events); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	for _, event := range events {
		status := evaluateEvent(event)
		storeEvent(event, status)

		if status == "blocked" {
			log.Printf("🚫 BLOCKED: %s (PID:%d) → %s:%d",
				event.Process, event.PID, event.DstIP, event.DstPort)
		}
	}

	c.JSON(200, gin.H{"received": len(events)})
}

func evaluateEvent(event NetworkEvent) string {
	configLock.RLock()
	mode := config.Mode
	configLock.RUnlock()

	rows, err := db.Query(`
		SELECT action FROM rules 
		WHERE (process = ? OR process = '*')
		AND (dst_ip = ? OR dst_ip = '*')
		AND (dst_port = ? OR dst_port = 0)
		ORDER BY id DESC LIMIT 1
	`, event.Process, event.DstIP, event.DstPort)

	if err != nil {
		return "allowed"
	}
	defer rows.Close()

	if rows.Next() {
		var action string
		rows.Scan(&action)
		if action == "deny" && mode == "enforce" {
			return "blocked"
		}
		return "allowed"
	}

	if mode == "enforce" {
		return "suspicious"
	}
	return "allowed"
}

func storeEvent(event NetworkEvent, status string) {
	_, err := db.Exec(`
		INSERT INTO events (hostname, pid, process, exe_path, event_type, 
							src_ip, src_port, dst_ip, dst_port, status, timestamp)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, event.Hostname, event.PID, event.Process, event.ExePath, event.EventType,
		event.SrcIP, event.SrcPort, event.DstIP, event.DstPort, status, time.Now())

	if err != nil {
		log.Printf("Failed to store event: %v", err)
	}
}

func getEvents(c *gin.Context) {
	limit := c.DefaultQuery("limit", "100")
	rows, err := db.Query(`
		SELECT hostname, pid, process, exe_path, event_type, src_ip, src_port,
			   dst_ip, dst_port, status, timestamp
		FROM events ORDER BY timestamp DESC LIMIT ?
	`, limit)

	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	events := []map[string]interface{}{}
	for rows.Next() {
		var e NetworkEvent
		var status string
		var timestamp time.Time
		rows.Scan(&e.Hostname, &e.PID, &e.Process, &e.ExePath, &e.EventType,
			&e.SrcIP, &e.SrcPort, &e.DstIP, &e.DstPort, &status, &timestamp)

		events = append(events, map[string]interface{}{
			"hostname":   e.Hostname,
			"pid":        e.PID,
			"process":    e.Process,
			"exe_path":   e.ExePath,
			"event_type": e.EventType,
			"src_ip":     e.SrcIP,
			"src_port":   e.SrcPort,
			"dst_ip":     e.DstIP,
			"dst_port":   e.DstPort,
			"status":     status,
			"timestamp":  timestamp.Format(time.RFC3339),
		})
	}

	c.JSON(200, events)
}

func getRules(c *gin.Context) {
	rows, err := db.Query(`SELECT id, process, dst_ip, dst_port, action, created_at FROM rules`)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	rules := []Rule{}
	for rows.Next() {
		var r Rule
		var createdAt time.Time
		rows.Scan(&r.ID, &r.Process, &r.DstIP, &r.DstPort, &r.Action, &createdAt)
		r.CreatedAt = createdAt.Format(time.RFC3339)
		rules = append(rules, r)
	}

	c.JSON(200, rules)
}

func addRule(c *gin.Context) {
	var rule Rule
	if err := c.BindJSON(&rule); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	result, err := db.Exec(`
		INSERT INTO rules (process, dst_ip, dst_port, action, created_at)
		VALUES (?, ?, ?, ?, datetime('now'))
	`, rule.Process, rule.DstIP, rule.DstPort, rule.Action)

	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	id, _ := result.LastInsertId()
	rule.ID = int(id)
	c.JSON(200, rule)
}

func deleteRule(c *gin.Context) {
	id := c.Param("id")
	_, err := db.Exec("DELETE FROM rules WHERE id = ?", id)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"deleted": id})
}

func getConfig(c *gin.Context) {
	configLock.RLock()
	defer configLock.RUnlock()
	c.JSON(200, config)
}

func updateConfig(c *gin.Context) {
	var newConfig Config
	if err := c.BindJSON(&newConfig); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	configLock.Lock()
	config = newConfig
	configLock.Unlock()

	log.Printf("📝 Config updated: mode=%s", config.Mode)
	c.JSON(200, config)
}

func getStats(c *gin.Context) {
	var total, allowed, blocked, suspicious int

	db.QueryRow("SELECT COUNT(*) FROM events").Scan(&total)
	db.QueryRow("SELECT COUNT(*) FROM events WHERE status='allowed'").Scan(&allowed)
	db.QueryRow("SELECT COUNT(*) FROM events WHERE status='blocked'").Scan(&blocked)
	db.QueryRow("SELECT COUNT(*) FROM events WHERE status='suspicious'").Scan(&suspicious)

	c.JSON(200, gin.H{
		"total":      total,
		"allowed":    allowed,
		"blocked":    blocked,
		"suspicious": suspicious,
		"mode":       config.Mode,
	})
}