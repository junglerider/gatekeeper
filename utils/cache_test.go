package utils

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCache(t *testing.T) {
	cache := NewCache[string, int]()
	require.NotNil(t, cache)
	require.NotNil(t, cache.items)
}

func TestCacheOperations(t *testing.T) {
	cache := NewCache[string, int]()

	t.Run("set and get", func(t *testing.T) {
		// Test setting and getting a value
		cache.Set("key1", 100)
		value, found := cache.Get("key1")
		assert.True(t, found)
		assert.Equal(t, 100, value)

		// Test getting a non-existent key
		value, found = cache.Get("nonexistent")
		assert.False(t, found)
		assert.Zero(t, value)
	})

	t.Run("delete", func(t *testing.T) {
		// Set and verify a value exists
		cache.Set("key2", 200)
		value, found := cache.Get("key2")
		assert.True(t, found)
		assert.Equal(t, 200, value)

		// Delete the value
		cache.Delete("key2")
		value, found = cache.Get("key2")
		assert.False(t, found)
		assert.Zero(t, value)

		// Delete a non-existent key (should not panic)
		cache.Delete("nonexistent")
	})

	t.Run("pop", func(t *testing.T) {
		// Set a value
		cache.Set("key3", 300)

		// Pop the value
		value, found := cache.Pop("key3")
		assert.True(t, found)
		assert.Equal(t, 300, value)

		// Verify the value was removed
		value, found = cache.Get("key3")
		assert.False(t, found)
		assert.Zero(t, value)

		// Pop a non-existent key
		value, found = cache.Pop("nonexistent")
		assert.False(t, found)
		assert.Zero(t, value)
	})
}

func TestCacheConcurrency(t *testing.T) {
	cache := NewCache[int, string]()
	const numGoroutines = 100
	const numOperations = 1000

	t.Run("concurrent set and get", func(t *testing.T) {
		var wg sync.WaitGroup
		wg.Add(numGoroutines * 2) // For both readers and writers

		// Writers
		for i := 0; i < numGoroutines; i++ {
			go func(base int) {
				defer wg.Done()
				for j := 0; j < numOperations; j++ {
					key := base*numOperations + j
					cache.Set(key, "value")
				}
			}(i)
		}

		// Readers
		for i := 0; i < numGoroutines; i++ {
			go func(base int) {
				defer wg.Done()
				for j := 0; j < numOperations; j++ {
					key := base*numOperations + j
					cache.Get(key)
				}
			}(i)
		}

		wg.Wait()
	})

	t.Run("concurrent set and delete", func(t *testing.T) {
		var wg sync.WaitGroup
		wg.Add(numGoroutines * 2)

		// Writers
		for i := 0; i < numGoroutines; i++ {
			go func(base int) {
				defer wg.Done()
				for j := 0; j < numOperations; j++ {
					key := base*numOperations + j
					cache.Set(key, "value")
				}
			}(i)
		}

		// Deleters
		for i := 0; i < numGoroutines; i++ {
			go func(base int) {
				defer wg.Done()
				for j := 0; j < numOperations; j++ {
					key := base*numOperations + j
					cache.Delete(key)
				}
			}(i)
		}

		wg.Wait()
	})

	t.Run("concurrent pop operations", func(t *testing.T) {
		// Pre-populate the cache
		for i := 0; i < numGoroutines*numOperations; i++ {
			cache.Set(i, "value")
		}

		var wg sync.WaitGroup
		wg.Add(numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func(base int) {
				defer wg.Done()
				for j := 0; j < numOperations; j++ {
					key := base*numOperations + j
					cache.Pop(key)
				}
			}(i)
		}

		wg.Wait()
	})
}

func TestCacheWithCustomTypes(t *testing.T) {
	type CustomKey struct {
		ID   int
		Name string
	}

	type CustomValue struct {
		Data     string
		Modified time.Time
	}

	cache := NewCache[CustomKey, CustomValue]()

	t.Run("custom types operations", func(t *testing.T) {
		key := CustomKey{ID: 1, Name: "test"}
		value := CustomValue{
			Data:     "test data",
			Modified: time.Now(),
		}

		// Set and Get
		cache.Set(key, value)
		retrieved, found := cache.Get(key)
		assert.True(t, found)
		assert.Equal(t, value, retrieved)

		// Delete
		cache.Delete(key)
		_, found = cache.Get(key)
		assert.False(t, found)

		// Pop
		cache.Set(key, value)
		popped, found := cache.Pop(key)
		assert.True(t, found)
		assert.Equal(t, value, popped)
		_, found = cache.Get(key)
		assert.False(t, found)
	})
}

func TestCacheEdgeCases(t *testing.T) {
	cache := NewCache[string, *string]()

	t.Run("nil values", func(t *testing.T) {
		// Set nil value
		cache.Set("nil-key", nil)
		value, found := cache.Get("nil-key")
		assert.True(t, found)
		assert.Nil(t, value)

		// Pop nil value
		value, found = cache.Pop("nil-key")
		assert.True(t, found)
		assert.Nil(t, value)
	})

	t.Run("empty string key", func(t *testing.T) {
		str := "test"
		cache.Set("", &str)
		value, found := cache.Get("")
		assert.True(t, found)
		assert.Equal(t, &str, value)
	})

	t.Run("zero values", func(t *testing.T) {
		zeroCache := NewCache[int, int]()
		zeroCache.Set(0, 0)
		value, found := zeroCache.Get(0)
		assert.True(t, found)
		assert.Zero(t, value)
	})
}
