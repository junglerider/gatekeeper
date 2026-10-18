package middleware

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequestLogger(t *testing.T) {
	// Create a simple handler for testing
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	})

	tests := []struct {
		name        string
		prettyPrint bool
		setup       func(*http.Request)
		validate    func(*testing.T, *httptest.ResponseRecorder, string)
	}{
		{
			name:        "JSON logging",
			prettyPrint: false,
			setup: func(r *http.Request) {
				r.Header.Set("X-Forwarded-For", "203.0.113.1")
			},
			validate: func(t *testing.T, rec *httptest.ResponseRecorder, output string) {
				// Verify JSON format
				var logEntry requestLog
				err := json.Unmarshal([]byte(output), &logEntry)
				require.NoError(t, err)

				assert.Equal(t, "request", logEntry.Level)
				assert.Equal(t, "GET", logEntry.Method)
				assert.Equal(t, 200, logEntry.StatusCode)
				assert.Equal(t, "203.0.113.1", logEntry.IP)
			},
		},
		{
			name:        "Pretty print logging",
			prettyPrint: true,
			setup: func(r *http.Request) {
				r.Header.Set("X-Real-Ip", "203.0.113.2")
			},
			validate: func(t *testing.T, rec *httptest.ResponseRecorder, output string) {
				// Verify pretty print format
				assert.Contains(t, output, "GET")
				assert.Contains(t, output, "203.0.113.2")
				assert.Contains(t, output, "200")
				assert.Contains(t, output, "\033[") // Contains ANSI color codes
			},
		},
		{
			name:        "Private IP filtering",
			prettyPrint: false,
			setup: func(r *http.Request) {
				r.Header.Set("X-Forwarded-For", "192.168.1.1, 203.0.113.3")
			},
			validate: func(t *testing.T, rec *httptest.ResponseRecorder, output string) {
				var logEntry requestLog
				err := json.Unmarshal([]byte(output), &logEntry)
				require.NoError(t, err)
				assert.Equal(t, "203.0.113.3", logEntry.IP)
			},
		},
		{
			name:        "Multiple X-Forwarded-For IPs",
			prettyPrint: false,
			setup: func(r *http.Request) {
				r.Header.Set("X-Forwarded-For", "203.0.113.4, 203.0.113.5, 203.0.113.6")
			},
			validate: func(t *testing.T, rec *httptest.ResponseRecorder, output string) {
				var logEntry requestLog
				err := json.Unmarshal([]byte(output), &logEntry)
				require.NoError(t, err)
				assert.Equal(t, "203.0.113.4", logEntry.IP)
			},
		},
		{
			name:        "No IP headers",
			prettyPrint: false,
			setup:       func(r *http.Request) {},
			validate: func(t *testing.T, rec *httptest.ResponseRecorder, output string) {
				var logEntry requestLog
				err := json.Unmarshal([]byte(output), &logEntry)
				require.NoError(t, err)
				assert.Empty(t, logEntry.IP)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture stdout
			old := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			// Create test request
			req := httptest.NewRequest("GET", "/test", nil)
			tt.setup(req)
			rec := httptest.NewRecorder()

			// Apply middleware
			handler := RequestLogger(tt.prettyPrint)(testHandler)
			handler.ServeHTTP(rec, req)

			// Read captured output
			w.Close()
			var buf bytes.Buffer
			_, err := buf.ReadFrom(r)
			require.NoError(t, err)
			os.Stdout = old

			output := strings.TrimSpace(buf.String())
			tt.validate(t, rec, output)
		})
	}
}

func TestMethodColor(t *testing.T) {
	tests := []struct {
		method string
		want   string
	}{
		{"GET", termColor["green"]},
		{"HEAD", termColor["green"]},
		{"POST", termColor["yellow"]},
		{"PUT", termColor["yellow"]},
		{"PATCH", termColor["yellow"]},
		{"DELETE", termColor["red"]},
		{"OPTIONS", termColor["reset"]},
		{"", termColor["reset"]},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := methodColor(tt.method)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestStatusColor(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		want       string
	}{
		{"1xx", 100, termColor["bgBlue"]},
		{"2xx", 200, termColor["bgGreen"]},
		{"3xx", 301, termColor["bgCyan"]},
		{"4xx", 404, termColor["bgYellow"]},
		{"5xx", 500, termColor["bgRed"]},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := statusColor(tt.statusCode)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestResponseRecorder(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
	}{
		{"OK status", http.StatusOK},
		{"Not Found status", http.StatusNotFound},
		{"Server Error status", http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &responseRecorder{
				ResponseWriter: httptest.NewRecorder(),
				statusCode:     http.StatusOK,
			}

			rec.WriteHeader(tt.statusCode)
			assert.Equal(t, tt.statusCode, rec.statusCode)
		})
	}
}

func TestGetIPAddress(t *testing.T) {
	tests := []struct {
		name        string
		headers     map[string]string
		expectedIP  string
		description string
	}{
		{
			name: "X-Forwarded-For single IP",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.1",
			},
			expectedIP:  "203.0.113.1",
			description: "Should return the single IP from X-Forwarded-For",
		},
		{
			name: "X-Forwarded-For multiple IPs",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.1, 203.0.113.2",
			},
			expectedIP:  "203.0.113.1",
			description: "Should return the leftmost public IP",
		},
		{
			name: "X-Real-IP",
			headers: map[string]string{
				"X-Real-Ip": "203.0.113.3",
			},
			expectedIP:  "203.0.113.3",
			description: "Should return X-Real-IP when X-Forwarded-For is absent",
		},
		{
			name: "Private IP filtering",
			headers: map[string]string{
				"X-Forwarded-For": "192.168.1.1, 203.0.113.4",
			},
			expectedIP:  "203.0.113.4",
			description: "Should filter out private IPs",
		},
		{
			name: "All private IPs",
			headers: map[string]string{
				"X-Forwarded-For": "192.168.1.1, 10.0.0.1, 172.16.0.1",
			},
			expectedIP:  "",
			description: "Should return empty string when all IPs are private",
		},
		{
			name:        "No headers",
			headers:     map[string]string{},
			expectedIP:  "",
			description: "Should return empty string when no headers present",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			ip := GetIPAdress(req)
			assert.Equal(t, tt.expectedIP, ip, tt.description)
		})
	}
}

func TestPrivateIPRanges(t *testing.T) {
	tests := []struct {
		name      string
		ip        string
		isPrivate bool
	}{
		{"Private 10.x.x.x", "10.0.0.1", true},
		{"Private 192.168.x.x", "192.168.1.1", true},
		{"Private 172.16.x.x", "172.16.0.1", true},
		{"Public IP", "203.0.113.1", false},
		{"Localhost", "127.0.0.1", false},
		{"Invalid IP", "invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip != nil {
				result := isPrivateSubnet(ip)
				assert.Equal(t, tt.isPrivate, result)
			}
		})
	}
}

func TestInRange(t *testing.T) {
	tests := []struct {
		name     string
		ipRange  ipRange
		testIP   string
		expected bool
	}{
		{
			name: "IP in range",
			ipRange: ipRange{
				start: net.ParseIP("192.168.0.0"),
				end:   net.ParseIP("192.168.255.255"),
			},
			testIP:   "192.168.1.1",
			expected: true,
		},
		{
			name: "IP not in range",
			ipRange: ipRange{
				start: net.ParseIP("192.168.0.0"),
				end:   net.ParseIP("192.168.255.255"),
			},
			testIP:   "192.169.1.1",
			expected: false,
		},
		{
			name: "IP at range start",
			ipRange: ipRange{
				start: net.ParseIP("10.0.0.0"),
				end:   net.ParseIP("10.255.255.255"),
			},
			testIP:   "10.0.0.0",
			expected: true,
		},
		{
			name: "IP at range end",
			ipRange: ipRange{
				start: net.ParseIP("10.0.0.0"),
				end:   net.ParseIP("10.255.255.255"),
			},
			testIP:   "10.255.255.255",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.testIP)
			result := inRange(tt.ipRange, ip)
			assert.Equal(t, tt.expected, result)
		})
	}
}
