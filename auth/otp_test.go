package auth

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"junglerider/gatekeeper/app"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xlzd/gotp"
)

func TestVerifyOTP(t *testing.T) {
	// Generate a test secret
	secret := gotp.RandomSecret(20)
	totp := gotp.NewDefaultTOTP(secret)

	// Generate current valid OTP
	validOTP := totp.Now()

	tests := []struct {
		name       string
		otp        string
		secret     string
		wantResult bool
	}{
		{
			name:       "Valid OTP",
			otp:        validOTP,
			secret:     secret,
			wantResult: true,
		},
		{
			name:       "Invalid OTP",
			otp:        "123456",
			secret:     secret,
			wantResult: false,
		},
		{
			name:       "Empty OTP",
			otp:        "",
			secret:     secret,
			wantResult: false,
		},
		{
			name:       "Empty Secret",
			otp:        validOTP,
			secret:     "",
			wantResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := VerifyOTP(tt.otp, tt.secret)
			assert.Equal(t, tt.wantResult, result)
		})
	}
}

func TestGenURIHandler(t *testing.T) {
	_, r := setupTestRouter()

	validParams := OTPParams{
		Secret:  "ABCDEFGHIJKLMNOPQRST",
		Name:    "testuser",
		Service: "testservice",
	}

	tests := []struct {
		name             string
		method           string
		params           OTPParams
		expectedStatus   int
		validateResponse func(t *testing.T, response map[string]interface{})
	}{
		{
			name:           "Valid request",
			method:         http.MethodPost,
			params:         validParams,
			expectedStatus: http.StatusOK,
			validateResponse: func(t *testing.T, response map[string]interface{}) {
				uri, ok := response["uri"].(string)
				require.True(t, ok)
				assert.Contains(t, uri, "otpauth://totp/")
				assert.Contains(t, uri, validParams.Secret)
				assert.Contains(t, uri, validParams.Name)
				assert.Contains(t, uri, validParams.Service)
			},
		},
		{
			name:   "Empty secret",
			method: http.MethodPost,
			params: OTPParams{
				Secret:  "",
				Name:    "testuser",
				Service: "testservice",
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:   "Empty name",
			method: http.MethodPost,
			params: OTPParams{
				Secret:  "ABCDEFGHIJKLMNOPQRST",
				Name:    "",
				Service: "testservice",
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:   "Empty service",
			method: http.MethodPost,
			params: OTPParams{
				Secret:  "ABCDEFGHIJKLMNOPQRST",
				Name:    "testuser",
				Service: "",
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Invalid method",
			method:         http.MethodGet,
			params:         validParams,
			expectedStatus: http.StatusMethodNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.params)
			require.NoError(t, err)

			req := httptest.NewRequest(tt.method, "/otp/uri", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectedStatus == http.StatusOK {
				var response map[string]interface{}
				err := json.NewDecoder(w.Body).Decode(&response)
				require.NoError(t, err)
				if tt.validateResponse != nil {
					tt.validateResponse(t, response)
				}
			}
		})
	}
}

func TestGenQRCodeHandler(t *testing.T) {
	_, r := setupTestRouter()

	validParams := OTPParams{
		Secret:  "ABCDEFGHIJKLMNOPQRST",
		Name:    "testuser",
		Service: "testservice",
	}

	tests := []struct {
		name             string
		method           string
		params           OTPParams
		expectedStatus   int
		validateResponse func(t *testing.T, headers http.Header, body []byte)
	}{
		{
			name:           "Valid request",
			method:         http.MethodPost,
			params:         validParams,
			expectedStatus: http.StatusOK,
			validateResponse: func(t *testing.T, headers http.Header, body []byte) {
				assert.Equal(t, "image/svg+xml", headers.Get("Content-Type"))
				assert.Equal(t, "*", headers.Get("Access-Control-Allow-Origin"))
				assert.Contains(t, string(body), "<svg")
				assert.Contains(t, string(body), "</svg>")
			},
		},
		{
			name:   "Invalid secret",
			method: http.MethodPost,
			params: OTPParams{
				Secret:  "",
				Name:    "testuser",
				Service: "testservice",
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Invalid method",
			method:         http.MethodGet,
			params:         validParams,
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:   "Special characters in parameters",
			method: http.MethodPost,
			params: OTPParams{
				Secret:  "ABCDEFGHIJKLMNOPQRST",
				Name:    "test@user.com",
				Service: "Test Service & Co.",
			},
			expectedStatus: http.StatusOK,
			validateResponse: func(t *testing.T, headers http.Header, body []byte) {
				assert.Equal(t, "image/svg+xml", headers.Get("Content-Type"))
				assert.Contains(t, string(body), "<svg")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.params)
			require.NoError(t, err)

			req := httptest.NewRequest(tt.method, "/otp/qrcode", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectedStatus == http.StatusOK {
				responseBody, err := io.ReadAll(w.Body)
				require.NoError(t, err)
				if tt.validateResponse != nil {
					tt.validateResponse(t, w.Header(), responseBody)
				}
			}
		})
	}
}

func setupTestRouter() (*Controller, *chi.Mux) {
	ctx := NewController(&app.Config{})
	r := chi.NewRouter()
	ctx.RegisterRoutes(r, r)
	return ctx, r
}

func TestGenSecretHandler(t *testing.T) {
	_, r := setupTestRouter()

	tests := []struct {
		name           string
		method         string
		expectedStatus int
	}{
		{
			name:           "Valid GET request",
			method:         http.MethodGet,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Invalid POST request",
			method:         http.MethodPost,
			expectedStatus: http.StatusMethodNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/otp/secret", nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectedStatus == http.StatusOK {
				var response map[string]interface{}
				err := json.NewDecoder(w.Body).Decode(&response)
				require.NoError(t, err)

				// Verify response structure
				secret, ok := response["otpSecret"]
				require.True(t, ok, "Response should contain otpSecret")
				require.NotEmpty(t, secret, "Secret should not be empty")

				// Verify secret length (base32 encoded 20-byte secret)
				assert.Len(t, secret.(string), 32)
			}
		})
	}
}

func TestOTPParamsToURI(t *testing.T) {
	tests := []struct {
		name       string
		params     OTPParams
		wantPrefix string
	}{
		{
			name: "Basic URI",
			params: OTPParams{
				Secret:  "ABCDEFGHIJKLMNOPQRST",
				Name:    "testuser",
				Service: "testservice",
			},
			wantPrefix: "otpauth://totp/testservice:testuser?issuer=testservice&secret=ABCDEFGHIJKLMNOPQRST",
		},
		{
			name: "URI with special characters",
			params: OTPParams{
				Secret:  "ABCDEFGHIJKLMNOPQRST",
				Name:    "user@example.com",
				Service: "Test Service",
			},
			wantPrefix: "otpauth://totp/Test%2520Service:user@example.com?issuer=Test%2BService&secret=ABCDEFGHIJKLMNOPQRST",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uri := otpParamsToURI(tt.params)
			assert.Contains(t, uri, tt.wantPrefix)
		})
	}
}
