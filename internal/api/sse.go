package api

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"dns-supreme-mini/internal/auth"
	"github.com/gin-gonic/gin"
)

type sseHub struct {
	clients map[chan string]bool
	mu      sync.RWMutex
}

func newSSEHub() *sseHub {
	return &sseHub{
		clients: make(map[chan string]bool),
	}
}

func (h *sseHub) addClient() chan string {
	ch := make(chan string, 16)
	h.mu.Lock()
	h.clients[ch] = true
	h.mu.Unlock()
	return ch
}

func (h *sseHub) removeClient(ch chan string) {
	h.mu.Lock()
	if _, ok := h.clients[ch]; ok {
		delete(h.clients, ch)
		close(ch)
	}
	h.mu.Unlock()
}

func (h *sseHub) broadcast(event, data string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	msg := fmt.Sprintf("event: %s\ndata: %s\n\n", event, data)
	for ch := range h.clients {
		select {
		case ch <- msg:
		default:
			// Client too slow, remove it
			delete(h.clients, ch)
			close(ch)
		}
	}
}

func (s *Server) sseHandler(c *gin.Context) {
	// Manual auth for SSE (EventSource can't send custom headers)
	token := c.Query("token")
	if token == "" {
		token = strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
	}
	if token == "" {
		c.JSON(401, gin.H{"error": "token required"})
		return
	}
	claims, err := auth.ValidateToken(token)
	if err != nil || !claims.MFADone {
		c.JSON(401, gin.H{"error": "invalid token"})
		return
	}

	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")

	ch := s.sseHub.addClient()
	defer s.sseHub.removeClient(ch)

	// Send initial stats immediately
	if stats, err := s.db.GetStats(1); err == nil {
		if data, err := json.Marshal(stats); err == nil {
			fmt.Fprintf(c.Writer, "event: stats\ndata: %s\n\n", data)
			c.Writer.Flush()
		}
	}

	ctx := c.Request.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			io.WriteString(c.Writer, msg)
			c.Writer.Flush()
		}
	}
}

func (s *Server) broadcastStats() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if s.sseHub == nil {
			continue
		}
		s.sseHub.mu.RLock()
		hasClients := len(s.sseHub.clients) > 0
		s.sseHub.mu.RUnlock()
		if !hasClients {
			continue
		}

		stats, err := s.db.GetStats(1)
		if err != nil {
			continue
		}
		data, err := json.Marshal(stats)
		if err != nil {
			continue
		}
		s.sseHub.broadcast("stats", string(data))
	}
}
