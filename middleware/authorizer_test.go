package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// stub verifier mapping token names to claims
func stubVerifier(token string) (map[string]any, error) {
	gatekeeper := func(values ...any) map[string]any {
		return map[string]any{"access": map[string]any{"gatekeeper": values}}
	}
	switch token {
	case "admin":
		return gatekeeper("admin"), nil
	case "read":
		return gatekeeper("read"), nil
	case "unknown":
		return gatekeeper("write", 1), nil
	case "string-list":
		return map[string]any{"access": map[string]any{"gatekeeper": []string{"read"}}}, nil
	case "not-a-list":
		return map[string]any{"access": map[string]any{"gatekeeper": "admin"}}, nil
	case "other-property":
		return map[string]any{"access": map[string]any{"other": []any{"admin"}}}, nil
	case "access-not-object":
		return map[string]any{"access": []any{"admin"}}, nil
	case "no-access":
		return map[string]any{}, nil
	}
	return nil, errors.New("invalid token")
}

func TestAuthorizer(t *testing.T) {
	reached := false
	handler := Authorizer(stubVerifier)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name   string
		method string
		header string
		status int
	}{
		{"admin can read", http.MethodGet, "Bearer admin", 200},
		{"admin can write", http.MethodPost, "Bearer admin", 200},
		{"admin can delete", http.MethodDelete, "Bearer admin", 200},
		{"lowercase scheme accepted", http.MethodGet, "bearer admin", 200},
		{"read can GET", http.MethodGet, "Bearer read", 200},
		{"read can HEAD", http.MethodHead, "Bearer read", 200},
		{"read as string slice", http.MethodGet, "Bearer string-list", 200},
		{"read cannot POST", http.MethodPost, "Bearer read", 403},
		{"read cannot PUT", http.MethodPut, "Bearer read", 403},
		{"read cannot DELETE", http.MethodDelete, "Bearer read", 403},
		{"no access claim", http.MethodGet, "Bearer no-access", 403},
		{"other property only", http.MethodGet, "Bearer other-property", 403},
		{"gatekeeper not a list", http.MethodGet, "Bearer not-a-list", 403},
		{"unknown permission", http.MethodGet, "Bearer unknown", 403},
		{"access not an object", http.MethodGet, "Bearer access-not-object", 403},
		{"invalid token", http.MethodGet, "Bearer garbage", 401},
		{"missing header", http.MethodGet, "", 401},
		{"wrong scheme", http.MethodGet, "Basic admin", 401},
		{"empty token", http.MethodGet, "Bearer ", 401},
		{"scheme only", http.MethodGet, "Bearer", 401},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reached = false
			req := httptest.NewRequest(tt.method, "/clients", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			assert.Equal(t, tt.status, rr.Code)
			assert.Equal(t, tt.status == 200, reached)
			if tt.status == 401 {
				assert.Equal(t, "Bearer", rr.Header().Get("WWW-Authenticate"))
			}
			if tt.status >= 400 {
				assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
				assert.Contains(t, rr.Body.String(), http.StatusText(tt.status))
			}
		})
	}
}
