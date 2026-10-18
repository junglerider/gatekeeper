package utils

// basic in-memory key-value cache implementation

import (
	"sync"
)

// basic in-memory key-value cache implementation
type Cache[K comparable, V any] struct {
	items map[K]V    // the map storing key-value pairs
	mu    sync.Mutex // mutex for controlling concurrent access to the cache.
}

// creates a new cache instance
func NewCache[K comparable, V any]() *Cache[K, V] {
	return &Cache[K, V]{
		items: make(map[K]V),
	}
}

// adds or updates a key-value pair in the cache
func (c *Cache[K, V]) Set(key K, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key] = value
}

// retrieves the value associated with the given key from the cache
// boolean return value is false if no matching key is found
func (c *Cache[K, V]) Get(key K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	value, found := c.items[key]
	return value, found
}

// deletes the key-value pair with the specified key from the cache
func (c *Cache[K, V]) Delete(key K) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.items, key)
}

// returns and delete the value associated with the specified key from the cache
func (c *Cache[K, V]) Pop(key K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	value, found := c.items[key]
	if found {
		delete(c.items, key)
	}
	return value, found
}

// returns the number of items currently in the cache
func (c *Cache[K, V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}

// returns all keys in the cache
func (c *Cache[K, V]) Keys() []K {
	c.mu.Lock()
	defer c.mu.Unlock()
	keys := make([]K, 0, len(c.items))
	for k := range c.items {
		keys = append(keys, k)
	}
	return keys
}

// removes all entries from the cache
func (c *Cache[K, V]) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[K]V)
}
