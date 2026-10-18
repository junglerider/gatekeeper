package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStrToJSON(t *testing.T) {

	t.Run("valid JSON", func(t *testing.T) {
		s := `{"foo":123}`
		val, err := StrToJSON(&s)
		assert.NoError(t, err)
		assert.NotNil(t, val)
	})

	t.Run("invalid JSON", func(t *testing.T) {
		s := `{"foo":`
		val, err := StrToJSON(&s)
		assert.Error(t, err)
		assert.Nil(t, val)
	})

	t.Run("nil value", func(t *testing.T) {
		val, err := StrToJSON(nil)
		assert.NoError(t, err)
		assert.Nil(t, val)
	})
}

func TestJSONToStr(t *testing.T) {
	t.Run("valid JSON", func(t *testing.T) {
		obj := map[string]any{"foo": 1}
		var anyObj any = obj
		str, err := JSONToStr(&anyObj)
		assert.NoError(t, err)
		assert.NotNil(t, str)
		assert.JSONEq(t, `{"foo":1}`, *str)
	})

	t.Run("invalid object", func(t *testing.T) {
		var anyObj any = make(chan int)
		str, err := JSONToStr(&anyObj)
		assert.Error(t, err)
		assert.Nil(t, str)
	})

	t.Run("nil value", func(t *testing.T) {
		str, err := JSONToStr(nil)
		assert.NoError(t, err)
		assert.Nil(t, str)
	})
}
