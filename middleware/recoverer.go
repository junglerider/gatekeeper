package middleware

import (
	"fmt"
	"net/http"
	"runtime/debug"

	"github.com/rs/zerolog/log"
)

// catches request panic, prints a stack trace and returns 500 Server Error JSON response
func Recoverer(h http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				fmt.Println("Unexpected Panic:")
				debug.PrintStack()
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(500)
				response := `{ "statusCode": 500, "error": "Internal Server Error" }`
				if _, err := w.Write([]byte(response)); err != nil {
					log.Error().Err(err).Msg("output error")
				}
			}
		}()
		h.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}
