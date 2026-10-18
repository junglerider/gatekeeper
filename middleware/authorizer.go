package middleware

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"
)

// access claim property holding the gatekeeper permissions
const AccessProperty = "gatekeeper"

// verifies an access token and returns its claims
type VerifyFunc func(token string) (map[string]any, error)

// guards routes with an access token passed in the Authorization header. The "gatekeeper" property of
// the token's access claim must contain "admin" for any request or "read" for GET and HEAD requests.
func Authorizer(verify VerifyFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			scheme, token, found := strings.Cut(r.Header.Get("Authorization"), " ")
			token = strings.TrimSpace(token)
			if !found || !strings.EqualFold(scheme, "Bearer") || token == "" {
				w.Header().Set("WWW-Authenticate", "Bearer")
				replyError(w, http.StatusUnauthorized, "access token required")
				return
			}
			claims, err := verify(token)
			if err != nil {
				log.Debug().Err(err).Msg("invalid JWT access token")
				w.Header().Set("WWW-Authenticate", "Bearer")
				replyError(w, http.StatusUnauthorized, "invalid or expired access token")
				return
			}
			if !isPermitted(claims, r.Method) {
				replyError(w, http.StatusForbidden, "insufficient permissions")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// checks the gatekeeper permissions of the access claim against the request method
func isPermitted(claims map[string]any, method string) bool {
	access, ok := claims["access"].(map[string]any)
	if !ok {
		return false
	}
	var permissions []string
	switch values := access[AccessProperty].(type) {
	case []any:
		for _, v := range values {
			if s, ok := v.(string); ok {
				permissions = append(permissions, s)
			}
		}
	case []string:
		permissions = values
	}
	readOnly := method == http.MethodGet || method == http.MethodHead
	for _, permission := range permissions {
		if permission == "admin" || (readOnly && permission == "read") {
			return true
		}
	}
	return false
}

// writes a JSON error response
func replyError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	body, _ := json.Marshal(map[string]any{"statusCode": code, "error": http.StatusText(code), "message": message})
	if _, err := w.Write(body); err != nil {
		log.Error().Err(err).Msg("output error")
	}
}
