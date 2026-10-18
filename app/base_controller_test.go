package app

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReply(t *testing.T) {
	bc := BaseController{}
	rr := httptest.NewRecorder()
	data := []byte(`{"foo":"bar"}`)
	n := bc.Reply(rr, 201, data)
	assert.Equal(t, len(data), n)
	assert.Equal(t, 201, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	assert.JSONEq(t, `{"foo":"bar"}`, rr.Body.String())
}

func TestDataReply(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		bc := BaseController{}
		rr := httptest.NewRecorder()
		obj := map[string]any{"hello": "world", "countries": 195, "pi": 3.14, "active": true}
		n := bc.DataReply(rr, 200, obj)
		assert.True(t, n > 0)
		assert.Equal(t, 200, rr.Code)
		assert.JSONEq(t, `{"hello":"world", "countries": 195, "pi": 3.14, "active": true}`, rr.Body.String())
	})

	t.Run("marshall error", func(t *testing.T) {
		bc := BaseController{}
		rr := httptest.NewRecorder()
		// channels can't be marshaled to JSON
		ch := make(chan int)
		n := bc.DataReply(rr, 200, ch)
		assert.True(t, n > 0)
		assert.Equal(t, 500, rr.Code)
		assert.Contains(t, rr.Body.String(), "json: unsupported type")
	})

}

func TestStatusReply(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		bc := BaseController{}
		rr := httptest.NewRecorder()
		n := bc.StatusReply(rr, 404)
		assert.True(t, n > 0)
		assert.Equal(t, 404, rr.Code)
		var resp map[string]any
		json.Unmarshal(rr.Body.Bytes(), &resp)
		assert.Equal(t, float64(404), resp["statusCode"])
		assert.Equal(t, "Not Found", resp["error"])
	})

	t.Run("with message", func(t *testing.T) {
		bc := BaseController{}
		rr := httptest.NewRecorder()
		n := bc.StatusReply(rr, 200, "custom message")
		assert.True(t, n > 0)
		assert.Equal(t, 200, rr.Code)
		var resp map[string]any
		json.Unmarshal(rr.Body.Bytes(), &resp)
		assert.Equal(t, float64(200), resp["statusCode"])
		assert.Equal(t, "custom message", resp["message"])
	})
}

func TestValidateRealm(t *testing.T) {
	bc := BaseController{
		Config: &Config{
			Realms: map[string]RealmConfig{
				"api":   {},
				"admin": {},
			},
		},
	}

	assert.NoError(t, bc.ValidateRealm("api"))
	assert.NoError(t, bc.ValidateRealm("admin"))
	err := bc.ValidateRealm("unknown")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown realm specified")
}

func TestDefaultRealm(t *testing.T) {
	bc := BaseController{}
	assert.Equal(t, "api", bc.DefaultRealm(""))
	assert.Equal(t, "custom", bc.DefaultRealm("custom"))
}

func TestMinPasswordLength(t *testing.T) {
	bc := BaseController{
		Config: &Config{
			Realms: map[string]RealmConfig{
				"api":     {},
				"custom":  {MinPasswordLength: 14},
				"invalid": {MinPasswordLength: -1},
			},
		},
	}

	assert.Equal(t, 10, bc.MinPasswordLength("api"))
	assert.Equal(t, 14, bc.MinPasswordLength("custom"))
	assert.Equal(t, 10, bc.MinPasswordLength("invalid"))
}

func TestValidateStringPtr(t *testing.T) {
	bc := BaseController{}
	val := "hello"
	assert.NoError(t, bc.ValidateStringPtr(&val, "field", 1, 10, true))
	assert.NoError(t, bc.ValidateStringPtr(nil, "field", 1, 10, false))
	err := bc.ValidateStringPtr(nil, "field", 1, 10, true)
	assert.EqualError(t, err, "field is required")
}

func TestValidateString(t *testing.T) {
	bc := BaseController{}
	assert.NoError(t, bc.ValidateString("hello", "field", 1, 10, true))
	assert.NoError(t, bc.ValidateString("", "field", 1, 10, false))
	err := bc.ValidateString("", "field", 1, 10, true)
	assert.EqualError(t, err, "field is required")

	err = bc.ValidateString("a", "field", 2, 10, true)
	assert.EqualError(t, err, "field must be at least 2 characters")

	err = bc.ValidateString("toolongstring", "field", 1, 5, true)
	assert.EqualError(t, err, "field must not be longer than 5 characters")
}
