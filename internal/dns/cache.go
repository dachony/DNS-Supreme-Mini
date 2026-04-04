package dns

import (
	"container/heap"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type cacheEntry struct {
	msg       *dns.Msg
	expiresAt time.Time
	key       string
	index     int // heap index
}

type expiryHeap []*cacheEntry

func (h expiryHeap) Len() int            { return len(h) }
func (h expiryHeap) Less(i, j int) bool  { return h[i].expiresAt.Before(h[j].expiresAt) }
func (h expiryHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i]; h[i].index = i; h[j].index = j }
func (h *expiryHeap) Push(x any)         { e := x.(*cacheEntry); e.index = len(*h); *h = append(*h, e) }
func (h *expiryHeap) Pop() any {
	old := *h
	n := len(old)
	e := old[n-1]
	old[n-1] = nil
	e.index = -1
	*h = old[:n-1]
	return e
}

type Cache struct {
	maxSize int
	entries map[string]*cacheEntry
	heap    expiryHeap
	mu      sync.RWMutex
}

func NewCache(maxSize int) *Cache {
	c := &Cache{
		maxSize: maxSize,
		entries: make(map[string]*cacheEntry),
		heap:    make(expiryHeap, 0),
	}
	heap.Init(&c.heap)
	go c.cleanupLoop()
	return c
}

func (c *Cache) Get(key string) (*dns.Msg, bool) {
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()

	if !ok {
		return nil, false
	}
	if time.Now().After(entry.expiresAt) {
		c.mu.Lock()
		c.removeEntry(entry)
		c.mu.Unlock()
		return nil, false
	}
	return entry.msg.Copy(), true
}

func (c *Cache) Set(key string, msg *dns.Msg, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Update existing entry
	if existing, ok := c.entries[key]; ok {
		existing.msg = msg.Copy()
		existing.expiresAt = time.Now().Add(ttl)
		heap.Fix(&c.heap, existing.index)
		return
	}

	// Evict oldest if at capacity
	for len(c.entries) >= c.maxSize && c.heap.Len() > 0 {
		oldest := heap.Pop(&c.heap).(*cacheEntry)
		delete(c.entries, oldest.key)
	}

	entry := &cacheEntry{
		msg:       msg.Copy(),
		expiresAt: time.Now().Add(ttl),
		key:       key,
	}
	heap.Push(&c.heap, entry)
	c.entries[key] = entry
}

func (c *Cache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

func (c *Cache) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*cacheEntry)
	c.heap = make(expiryHeap, 0)
	heap.Init(&c.heap)
}

func (c *Cache) removeEntry(entry *cacheEntry) {
	if entry.index >= 0 && entry.index < c.heap.Len() {
		heap.Remove(&c.heap, entry.index)
	}
	delete(c.entries, entry.key)
}

func (c *Cache) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for c.heap.Len() > 0 && c.heap[0].expiresAt.Before(now) {
			entry := heap.Pop(&c.heap).(*cacheEntry)
			delete(c.entries, entry.key)
		}
		c.mu.Unlock()
	}
}
