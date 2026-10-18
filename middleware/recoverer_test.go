package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRecoverer_Panic(t *testing.T) {
	// Handler that panics
	panicHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	})

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	Recoverer(panicHandler).ServeHTTP(rr, req)

	assert.Equal(t, 500, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	assert.Contains(t, rr.Body.String(), `"statusCode": 500`)
	assert.Contains(t, rr.Body.String(), `"error": "Internal Server Error"`)
}

func TestRecoverer_NoPanic(t *testing.T) {
	// Handler that does not panic
	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`))
	})

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	Recoverer(okHandler).ServeHTTP(rr, req)

	assert.Equal(t, 200, rr.Code)
	assert.True(t, strings.Contains(rr.Body.String(), `"ok":true`))
}
