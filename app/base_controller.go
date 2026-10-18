package app

// base controller provides shared infrastructure functions for all controllers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"
)

type BaseController struct {
	Config *Config // application configuration
}

// writes the JSON response contained in bytes to the underlying ResponseWriter
func (bc *BaseController) Reply(w http.ResponseWriter, code int, bytes []byte) int {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if byteCount, err := w.Write(bytes); err != nil {
		log.Error().Err(err).Msg("JSON reply failed")
		return 0
	} else {
		return byteCount
	}

}

// writes the JSON response containing the given data to the underlying ResponseWriter
func (bc *BaseController) DataReply(w http.ResponseWriter, code int, data any) int {
	bytes, err := json.Marshal(data)
	if err != nil {
		log.Error().Err(err).Msg("JSON reply failed")
		return bc.StatusReply(w, 500, err.Error())
	}
	return bc.Reply(w, code, bytes)
}

// creates a JSON response with a status code and an optional message
func (bc *BaseController) StatusReply(w http.ResponseWriter, code int, messages ...string) int {
	reply := make(map[string]any)
	reply["statusCode"] = code
	statusText := http.StatusText(code)
	if code >= 400 && statusText != "" {
		reply["error"] = statusText
	}
	if len(messages) > 0 {
		reply["message"] = strings.Join(messages, "\n")
	} else if code < 400 && statusText != "" {
		reply["message"] = statusText
	}
	bytes, _ := json.Marshal(reply)
	return bc.Reply(w, code, bytes)
}

// validates a realm identifier
func (bc *BaseController) ValidateRealm(input string) error {
	if _, ok := bc.Config.Realms[input]; ok {
		return nil
	}
	return errors.New("unknown realm specified: " + input)
}

// returns realm identifier or default realm
func (bc *BaseController) DefaultRealm(input string) string {
	if input == "" {
		input = "api"
	}
	return input
}

func (bc *BaseController) MinPasswordLength(realm string) int {
	minLength := bc.Config.Realms[realm].MinPasswordLength
	if minLength <= 0 {
		return 10
	}
	return minLength
}

// validates an optional string input value
func (bc *BaseController) ValidateStringPtr(input *string, name string, minLength, maxLength int, required bool) error {
	if input == nil {
		if required {
			return errors.New(name + " is required")
		}
		return nil
	}
	return bc.ValidateString(*input, name, minLength, maxLength, required)
}

// validates a string input value
func (bc *BaseController) ValidateString(input, name string, minLength, maxLength int, required bool) error {
	if input == "" {
		if required {
			return errors.New(name + " is required")
		} else {
			return nil
		}
	}
	if len(input) < minLength {
		return fmt.Errorf("%s must be at least %d characters", name, minLength)
	}
	if len(input) > maxLength {
		return fmt.Errorf("%s must not be longer than %d characters", name, maxLength)
	}
	return nil
}
