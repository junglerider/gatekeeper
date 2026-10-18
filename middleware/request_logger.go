package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

type requestLog struct {
	Level      string `json:"level"`
	UnixTime   int64  `json:"time"`
	Method     string `json:"method"`
	URL        string `json:"url"`
	IP         string `json:"ip"`
	start      time.Time
	duration   time.Duration
	DurationMs int64 `json:"duration"`
	StatusCode int   `json:"status"`
}

// logs the following items for each HTTP request:
//   - date/time
//   - request method
//   - request host + URL
//   - remote IP address (if available and not private)
//   - HTTP response status code
//   - request duration
//
// if prettyPrint is enabled, a colored single line is printed for each request
// if disabled, zerolog-compatible JSON output is generated
func RequestLogger(prettyPrint bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reqLog := requestLog{Level: "request"}
			reqLog.start = time.Now()
			reqLog.UnixTime = time.Now().Unix()
			reqLog.Method = r.Method
			reqLog.URL = r.Host + r.URL.RequestURI()
			reqLog.IP = GetIPAdress(r)
			rec := &responseRecorder{ResponseWriter: w, statusCode: 200}
			next.ServeHTTP(rec, r)
			reqLog.StatusCode = rec.statusCode
			reqLog.duration = time.Since(reqLog.start)
			reqLog.DurationMs = reqLog.duration.Milliseconds()
			if prettyPrint {
				fmt.Println(prettyPrintLog(reqLog))
			} else {
				if b, err := json.Marshal(reqLog); err == nil {
					fmt.Println(string(b))
				}
			}
		})
	}
}

func prettyPrintLog(reqLog requestLog) string {
	var sb strings.Builder
	sb.WriteString("\033[38;5;243m")
	sb.WriteString(reqLog.start.Format("3:04PM"))
	sb.WriteString(termColor["reset"])
	sb.WriteRune(' ')
	sb.WriteString(methodColor(reqLog.Method))
	sb.WriteString(reqLog.Method)
	sb.WriteString(termColor["reset"])
	sb.WriteRune(' ')
	sb.WriteString(reqLog.URL)
	if reqLog.IP != "" {
		sb.WriteString(" from ")
		sb.WriteString(reqLog.IP)
	}
	sb.WriteRune(' ')
	sb.WriteString(statusColor(reqLog.StatusCode))
	fmt.Fprintf(&sb, " %d ", reqLog.StatusCode)
	sb.WriteString(termColor["reset"])
	sb.WriteRune(' ')
	sb.WriteString(reqLog.duration.String())
	return sb.String()
}

var termColor = map[string]string{
	"reset":     "\033[0m",
	"red":       "\033[31m",
	"bgRed":     "\033[41m",
	"green":     "\033[32m",
	"bgGreen":   "\033[30m\033[42m",
	"yellow":    "\033[33m",
	"bgYellow":  "\033[43m",
	"blue":      "\033[34m",
	"bgBlue":    "\033[44m",
	"magenta":   "\033[35m",
	"bgMagenta": "\033[45m",
	"cyan":      "\033[36m",
	"bgCyan":    "\033[46m",
	"gray":      "\033[37m",
	"bgGray":    "\033[47m",
	"white":     "\033[97m",
}

func methodColor(method string) string {
	switch method {
	case "GET", "HEAD":
		return termColor["green"]
	case "POST", "PUT", "PATCH":
		return termColor["yellow"]
	case "DELETE":
		return termColor["red"]
	}
	return termColor["reset"]
}

func statusColor(statusCode int) string {
	switch {
	case statusCode < 200:
		return termColor["bgBlue"]
	case statusCode < 300:
		return termColor["bgGreen"]
	case statusCode < 400:
		return termColor["bgCyan"]
	case statusCode < 500:
		return termColor["bgYellow"]
	default:
		return termColor["bgRed"]
	}
}

// ResponseWriter wrapper to capture the HTTP status code of response
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
}

// captures the status code for logging purposes
func (rec *responseRecorder) WriteHeader(code int) {
	rec.statusCode = code
	rec.ResponseWriter.WriteHeader(code)
}

type ipRange struct {
	start net.IP
	end   net.IP
}

// inRange - check to see if a given ip address is within a range given
func inRange(r ipRange, ipAddress net.IP) bool {
	// strcmp type byte comparison
	if bytes.Compare(ipAddress, r.start) >= 0 && bytes.Compare(ipAddress, r.end) < 0 {
		return true
	}
	return false
}

var privateRanges = []ipRange{
	{
		start: net.ParseIP("10.0.0.0"),
		end:   net.ParseIP("10.255.255.255"),
	}, {
		start: net.ParseIP("100.64.0.0"),
		end:   net.ParseIP("100.127.255.255"),
	}, {
		start: net.ParseIP("172.16.0.0"),
		end:   net.ParseIP("172.31.255.255"),
	}, {
		start: net.ParseIP("192.0.0.0"),
		end:   net.ParseIP("192.0.0.255"),
	}, {
		start: net.ParseIP("192.168.0.0"),
		end:   net.ParseIP("192.168.255.255"),
	}, {
		start: net.ParseIP("198.18.0.0"),
		end:   net.ParseIP("198.19.255.255"),
	},
}

// isPrivateSubnet - check to see if this ip is in a private subnet
func isPrivateSubnet(ipAddress net.IP) bool {
	// my use case is only concerned with ipv4 atm
	if ipCheck := ipAddress.To4(); ipCheck != nil {
		// iterate over all our ranges
		for _, r := range privateRanges {
			// check if this ip is in a private range
			if inRange(r, ipAddress) {
				return true
			}
		}
	}
	return false
}

func GetIPAdress(r *http.Request) string {
	for _, h := range []string{"X-Forwarded-For", "X-Real-Ip"} {
		addresses := strings.Split(r.Header.Get(h), ",")
		// march from right to left until we get a public address
		// that will be the address right before our proxy.
		for _, address := range addresses {
			ip := strings.TrimSpace(address)
			// header can contain spaces too, strip those out.
			realIP := net.ParseIP(ip)
			if !realIP.IsGlobalUnicast() || isPrivateSubnet(realIP) {
				// bad address, go to next
				continue
			}
			return ip
		}
	}
	return ""
}
