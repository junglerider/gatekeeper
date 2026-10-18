package client

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"junglerider/gatekeeper/app"
	"junglerider/gatekeeper/auth"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockClientRepo is a mock implementation of ClientRepo interface
type MockClientRepo struct {
	mock.Mock
}

func (m *MockClientRepo) ListClients(realm string, isActive *bool, expiry *time.Time) ([]string, error) {
	args := m.Called(realm, isActive, expiry)
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockClientRepo) ReadClient(realm string, clientID string) (*Client, error) {
	args := m.Called(realm, clientID)
	return args.Get(0).(*Client), args.Error(1)
}

func (m *MockClientRepo) CreateClient(client Client, realm string) error {
	args := m.Called(client, realm)
	return args.Error(0)
}

func (m *MockClientRepo) UpdateClient(clientID string, realm string, props map[string]any) (int64, error) {
	args := m.Called(clientID, realm, props)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockClientRepo) DeleteClient(clientID string, realm string) (int64, error) {
	args := m.Called(clientID, realm)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockClientRepo) LoginClient(login *Client, config *app.Config) (*auth.TokenPair, error) {
	args := m.Called(login, config)
	return args.Get(0).(*auth.TokenPair), args.Error(1)
}

func (m *MockClientRepo) VerifyAPIKey(apiKey string, realm string, config *app.Config) (map[string]any, error) {
	args := m.Called(apiKey, realm, config)
	return args.Get(0).(map[string]any), args.Error(1)
}

func (m *MockClientRepo) RefreshToken(claims jwt.MapClaims, realm string, config *app.Config) (*auth.TokenPair, error) {
	args := m.Called(claims, realm, config)
	return args.Get(0).(*auth.TokenPair), args.Error(1)
}

func (m *MockClientRepo) LogoutClient(claims jwt.MapClaims, realm string) error {
	args := m.Called(claims, realm)
	return args.Error(0)
}

// creates a test controller with mocked dependencies
func setupTestController(t *testing.T) (*Controller, *MockClientRepo, *app.Config) {
	mockRepo := new(MockClientRepo)
	signingPrivateKey, verificationPublicKey := testSigningKeys(2)
	config := &app.Config{
		Realms: map[string]app.RealmConfig{
			"test-realm": {
				SigningPrivateKey:     signingPrivateKey,
				VerificationPublicKey: verificationPublicKey,
				AccessTokenLifetime:   3600,
				RefreshTokenLifetime:  86400,
				SessionMaxLifetime:    604800,
				Claims:                map[string]any{"role": "client"},
			},
		},
		Server: app.Config{}.Server,
	}
	controller := &Controller{
		BaseController: &app.BaseController{
			Config: config,
		},
		repo: mockRepo,
	}
	return controller, mockRepo, config
}

// creates a valid token pair for testing
func setupTokenPair(t *testing.T) *auth.TokenPair {
	client := Client{
		ClientID: "client1",
		Realm:    "test-realm",
	}
	claims := map[string]any{}
	_, _, config := setupTestController(t)
	if tokenPair, _, err := auth.CreateTokenPair(&client, claims, *config); err != nil {
		t.Fatalf("failed to create token pair: %v", err)
		return nil
	} else {
		return tokenPair
	}
}

func TestListHandler(t *testing.T) {
	t.Run("Successful list", func(t *testing.T) {
		controller, mockRepo, _ := setupTestController(t)
		mockRepo.On("ListClients", "test-realm", (*bool)(nil), (*time.Time)(nil)).Return([]string{"client1", "client2"}, nil).Once()

		req, _ := http.NewRequest("GET", "/clients?realm=test-realm", nil)
		rr := httptest.NewRecorder()
		r := chi.NewRouter()
		r.Get("/clients", controller.listHandler)
		r.ServeHTTP(rr, req)

		assert.Equal(t, 200, rr.Code)
		var responseBody []string
		err := json.Unmarshal(rr.Body.Bytes(), &responseBody)
		assert.NoError(t, err)
		assert.Equal(t, []string{"client1", "client2"}, responseBody)
	})

	t.Run("Expiry filter", func(t *testing.T) {
		expiry := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
		controller, mockRepo, _ := setupTestController(t)
		mockRepo.On("ListClients", "test-realm", (*bool)(nil), &expiry).Return([]string{"client1"}, nil).Once()

		req, _ := http.NewRequest("GET", "/clients?realm=test-realm&expiry=2026-10-11T00:00:00Z", nil)
		rr := httptest.NewRecorder()
		r := chi.NewRouter()
		r.Get("/clients", controller.listHandler)
		r.ServeHTTP(rr, req)

		assert.Equal(t, 200, rr.Code)
	})

	t.Run("Invalid realm", func(t *testing.T) {
		controller, _, _ := setupTestController(t)

		req, _ := http.NewRequest("GET", "/clients?realm=invalid-realm", nil)
		rr := httptest.NewRecorder()
		r := chi.NewRouter()
		r.Get("/clients", controller.listHandler)
		r.ServeHTTP(rr, req)

		assert.Equal(t, 400, rr.Code)
		assert.Contains(t, rr.Body.String(), `"message":"unknown realm specified: invalid-realm"`)
	})

	t.Run("Repository error", func(t *testing.T) {
		controller, mockRepo, _ := setupTestController(t)
		mockRepo.On("ListClients", "test-realm", (*bool)(nil), (*time.Time)(nil)).Return([]string{}, errors.New("db error")).Once()

		req, _ := http.NewRequest("GET", "/clients?realm=test-realm", nil)
		rr := httptest.NewRecorder()
		r := chi.NewRouter()
		r.Get("/clients", controller.listHandler)
		r.ServeHTTP(rr, req)

		assert.Equal(t, 500, rr.Code)
	})
}

func TestReadHandler(t *testing.T) {
	pwd := "password"
	client := Client{
		ClientID: "client1",
		Realm:    "test-realm",
		Password: &pwd,
		APIKey:   &pwd,
	}

	t.Run("Successful read", func(t *testing.T) {
		controller, mockRepo, _ := setupTestController(t)
		mockRepo.On("ReadClient", "test-realm", "client1").Return(&client, nil).Once()

		req, _ := http.NewRequest("GET", "/clients/client1?realm=test-realm", nil)
		rr := httptest.NewRecorder()
		r := chi.NewRouter()
		r.Get("/clients/{clientId}", controller.readHandler)
		r.ServeHTTP(rr, req)

		assert.Equal(t, 200, rr.Code)
		var response Client
		err := json.Unmarshal(rr.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, client, response)
	})

	t.Run("Invalid realm", func(t *testing.T) {
		controller, _, _ := setupTestController(t)

		req, _ := http.NewRequest("GET", "/clients/client1?realm=unknown-realm", nil)
		rr := httptest.NewRecorder()
		r := chi.NewRouter()
		r.Get("/clients/{clientId}", controller.readHandler)
		r.ServeHTTP(rr, req)

		assert.Equal(t, 400, rr.Code)
		assert.Contains(t, rr.Body.String(), `"message":"unknown realm specified: unknown-realm"`)
	})

	t.Run("Not found", func(t *testing.T) {
		controller, mockRepo, _ := setupTestController(t)
		mockRepo.On("ReadClient", "test-realm", "client1").Return((*Client)(nil), sql.ErrNoRows).Once()

		req, _ := http.NewRequest("GET", "/clients/client1?realm=test-realm", nil)
		rr := httptest.NewRecorder()
		r := chi.NewRouter()
		r.Get("/clients/{clientId}", controller.readHandler)
		r.ServeHTTP(rr, req)

		assert.Equal(t, 404, rr.Code)
		assert.Contains(t, rr.Body.String(), `"error":"Not Found"`)
	})
}

func TestCreateHandler(t *testing.T) {
	pwd := "password123"
	active := true
	client := Client{
		ClientID: "client1",
		Realm:    "test-realm",
		Password: &pwd,
		IsActive: &active,
	}

	t.Run("Successful create", func(t *testing.T) {
		controller, mockRepo, _ := setupTestController(t)
		mockRepo.On("CreateClient", client, client.Realm).Return(nil).Once()

		body, _ := json.Marshal(client)
		req, _ := http.NewRequest("POST", "/clients", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()
		r := chi.NewRouter()
		r.Post("/clients", controller.createHandler)
		r.ServeHTTP(rr, req)

		assert.Equal(t, 201, rr.Code)
		var responseBody any
		if rr.Body.Len() > 0 {
			json.Unmarshal(rr.Body.Bytes(), &responseBody)
		}
		assert.Equal(t, map[string]any{
			"message":  "created",
			"realm":    "test-realm",
			"clientId": "client1",
		}, responseBody)
	})

	t.Run("Realm minimum password length", func(t *testing.T) {
		controller, _, config := setupTestController(t)
		realmConfig := config.Realms["test-realm"]
		realmConfig.MinPasswordLength = 14
		config.Realms["test-realm"] = realmConfig

		shortPasswordClient := client
		shortPassword := "password123"
		shortPasswordClient.Password = &shortPassword
		body, _ := json.Marshal(shortPasswordClient)
		req, _ := http.NewRequest("POST", "/clients", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()
		r := chi.NewRouter()
		r.Post("/clients", controller.createHandler)
		r.ServeHTTP(rr, req)

		assert.Equal(t, 400, rr.Code)
		assert.Contains(t, rr.Body.String(), "password must be at least 14 characters")
	})

	t.Run("Empty provided password", func(t *testing.T) {
		controller, _, _ := setupTestController(t)
		emptyPassword := ""
		clientWithAPIKey := Client{
			ClientID: "client1",
			Realm:    "test-realm",
			Password: &emptyPassword,
			APIKey:   PtrFacade("api-key-12345"),
		}
		body, _ := json.Marshal(clientWithAPIKey)
		req, _ := http.NewRequest("POST", "/clients", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()
		r := chi.NewRouter()
		r.Post("/clients", controller.createHandler)
		r.ServeHTTP(rr, req)

		assert.Equal(t, 400, rr.Code)
		assert.Contains(t, rr.Body.String(), "password is required")
	})

	t.Run("Invalid input", func(t *testing.T) {
		controller, _, _ := setupTestController(t)
		invalidClient := Client{
			ClientID: "",
			Realm:    "test-realm",
		}
		body, _ := json.Marshal(invalidClient)

		req, _ := http.NewRequest("POST", "/clients", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()
		r := chi.NewRouter()
		r.Post("/clients", controller.createHandler)
		r.ServeHTTP(rr, req)

		assert.Equal(t, 400, rr.Code)
		assert.Contains(t, rr.Body.String(), `"message":"client id is required"`)
	})

	t.Run("Duplicate error", func(t *testing.T) {
		controller, mockRepo, _ := setupTestController(t)
		mockRepo.On("CreateClient", client, client.Realm).Return(errors.New("Duplicate entry")).Once()

		body, _ := json.Marshal(client)
		req, _ := http.NewRequest("POST", "/clients", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()
		r := chi.NewRouter()
		r.Post("/clients", controller.createHandler)
		r.ServeHTTP(rr, req)

		assert.Equal(t, 409, rr.Code)
		assert.Contains(t, rr.Body.String(), `"message":"Duplicate entry"`)
	})
}

func TestUpdateHandler(t *testing.T) {
	updateProps := map[string]any{
		"access": map[string]any{"canRead": true, "canWrite": false},
	}
	expectedProps := map[string]interface{}{
		"access": `{"canRead":true,"canWrite":false}`,
	}
	t.Run("Successful update", func(t *testing.T) {
		controller, mockRepo, _ := setupTestController(t)
		mockRepo.On("UpdateClient", "client1", "test-realm", expectedProps).Return(int64(1), nil).Once()

		body, _ := json.Marshal(updateProps)
		req, _ := http.NewRequest("PATCH", "/clients/client1?realm=test-realm", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()
		r := chi.NewRouter()
		r.Patch("/clients/{clientId}", controller.updateHandler)
		r.ServeHTTP(rr, req)

		assert.Equal(t, 204, rr.Code)
		assert.Equal(t, 0, rr.Body.Len())
	})

	t.Run("Password expiry update", func(t *testing.T) {
		expiry := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
		expectedProps := map[string]any{"pwd_expiry": expiry}
		controller, mockRepo, _ := setupTestController(t)
		mockRepo.On("UpdateClient", "client1", "test-realm", expectedProps).Return(int64(1), nil).Once()

		body, _ := json.Marshal(map[string]string{"pwdExpiry": expiry.Format(time.RFC3339Nano)})
		req, _ := http.NewRequest("PATCH", "/clients/client1?realm=test-realm", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()
		r := chi.NewRouter()
		r.Patch("/clients/{clientId}", controller.updateHandler)
		r.ServeHTTP(rr, req)

		assert.Equal(t, 204, rr.Code)
	})

	t.Run("Realm minimum password length", func(t *testing.T) {
		controller, _, config := setupTestController(t)
		realmConfig := config.Realms["test-realm"]
		realmConfig.MinPasswordLength = 14
		config.Realms["test-realm"] = realmConfig

		body, _ := json.Marshal(map[string]string{"password": "password123"})
		req, _ := http.NewRequest("PATCH", "/clients/client1?realm=test-realm", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()
		r := chi.NewRouter()
		r.Patch("/clients/{clientId}", controller.updateHandler)
		r.ServeHTTP(rr, req)

		assert.Equal(t, 400, rr.Code)
		assert.Contains(t, rr.Body.String(), "password must be at least 14 characters")
	})

	t.Run("Invalid client ID", func(t *testing.T) {
		controller, mockRepo, _ := setupTestController(t)
		mockRepo.On("UpdateClient", "client1", "test-realm", expectedProps).Return(int64(1), nil).Once()
		body, _ := json.Marshal(updateProps)

		req, _ := http.NewRequest("PATCH", "/clients/client_id_is_too_long?realm=test-realm", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()
		r := chi.NewRouter()
		r.Patch("/clients/{clientId}", controller.updateHandler)
		r.ServeHTTP(rr, req)

		assert.Equal(t, 400, rr.Code)
		assert.Contains(t, rr.Body.String(), `"message":"client id must not be longer than 16 characters"`)
	})

	t.Run("Not found", func(t *testing.T) {
		controller, mockRepo, _ := setupTestController(t)
		mockRepo.On("UpdateClient", "client1", "test-realm", expectedProps).Return(int64(0), nil).Once()

		body, _ := json.Marshal(updateProps)
		req, _ := http.NewRequest("PATCH", "/clients/client1?realm=test-realm", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()
		r := chi.NewRouter()
		r.Patch("/clients/{clientId}", controller.updateHandler)
		r.ServeHTTP(rr, req)

		assert.Equal(t, 404, rr.Code)
		assert.Contains(t, rr.Body.String(), `"error":"Not Found"`)
	})
}

func TestDeleteHandler(t *testing.T) {
	t.Run("Successful delete", func(t *testing.T) {
		controller, mockRepo, _ := setupTestController(t)
		mockRepo.On("DeleteClient", "client1", "test-realm").Return(int64(1), nil).Once()

		req, _ := http.NewRequest("DELETE", "/clients/client1?realm=test-realm", nil)
		rr := httptest.NewRecorder()
		r := chi.NewRouter()
		r.Delete("/clients/{clientId}", controller.deleteHandler)
		r.ServeHTTP(rr, req)

		assert.Equal(t, 204, rr.Code)
		assert.Equal(t, 0, rr.Body.Len())
	})

	t.Run("Invalid client ID", func(t *testing.T) {
		controller, _, _ := setupTestController(t)

		req, _ := http.NewRequest("DELETE", "/clients/client1?realm=invalid-realm", nil)
		rr := httptest.NewRecorder()
		r := chi.NewRouter()
		r.Delete("/clients/{clientId}", controller.deleteHandler)
		r.ServeHTTP(rr, req)

		assert.Equal(t, 400, rr.Code)
		assert.Contains(t, rr.Body.String(), `"unknown realm specified: invalid-realm"`)
	})

	t.Run("Not found", func(t *testing.T) {
		controller, mockRepo, _ := setupTestController(t)
		mockRepo.On("DeleteClient", "client1", "test-realm").Return(int64(0), nil).Once()

		req, _ := http.NewRequest("DELETE", "/clients/client1?realm=test-realm", nil)
		rr := httptest.NewRecorder()
		r := chi.NewRouter()
		r.Delete("/clients/{clientId}", controller.deleteHandler)
		r.ServeHTTP(rr, req)

		assert.Equal(t, 404, rr.Code)
		assert.Contains(t, rr.Body.String(), `"error":"Not Found"`)
	})
}

func TestLoginHandler(t *testing.T) {
	client := Client{
		ClientID: "client1",
		Realm:    "test-realm",
		Password: new(string),
	}
	*client.Password = "password123"
	tokenPair := &auth.TokenPair{
		AccessToken:          "access-token",
		AccessTokenLifetime:  3600,
		RefreshToken:         "refresh-token",
		RefreshTokenLifetime: 86400,
	}

	t.Run("Successful login", func(t *testing.T) {
		controller, mockRepo, config := setupTestController(t)
		mockRepo.On("LoginClient", &client, config).Return(tokenPair, nil).Once()

		body, _ := json.Marshal(client)
		req, _ := http.NewRequest("POST", "/clients/login?realm=test-realm", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()
		r := chi.NewRouter()
		r.Post("/clients/login", controller.loginHandler)
		r.ServeHTTP(rr, req)

		assert.Equal(t, 200, rr.Code)
		var tp auth.TokenPair
		err := json.Unmarshal(rr.Body.Bytes(), &tp)
		assert.NoError(t, err)
		assert.Equal(t, *tokenPair, tp)
	})

	t.Run("Invalid credentials", func(t *testing.T) {
		controller, mockRepo, config := setupTestController(t)
		mockRepo.On("LoginClient", &client, config).Return((*auth.TokenPair)(nil), errors.New("access denied")).Once()

		body, _ := json.Marshal(client)
		req, _ := http.NewRequest("POST", "/clients/login?realm=test-realm", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()
		r := chi.NewRouter()
		r.Post("/clients/login", controller.loginHandler)
		r.ServeHTTP(rr, req)

		assert.Equal(t, 401, rr.Code)
		assert.Contains(t, rr.Body.String(), `"credentials not recognised"`)
	})

	t.Run("Expired password", func(t *testing.T) {
		controller, mockRepo, config := setupTestController(t)
		mockRepo.On("LoginClient", &client, config).Return((*auth.TokenPair)(nil), errPasswordExpired).Once()

		body, _ := json.Marshal(client)
		req, _ := http.NewRequest("POST", "/clients/login?realm=test-realm", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()
		r := chi.NewRouter()
		r.Post("/clients/login", controller.loginHandler)
		r.ServeHTTP(rr, req)

		assert.Equal(t, 401, rr.Code)
		assert.Contains(t, rr.Body.String(), `"message":"password expired"`)
	})

	t.Run("Invalid input", func(t *testing.T) {
		controller, _, _ := setupTestController(t)
		invalidClient := Client{
			ClientID: "",
			Realm:    "test-realm",
		}
		body, _ := json.Marshal(invalidClient)

		req, _ := http.NewRequest("POST", "/clients/login", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()
		r := chi.NewRouter()
		r.Post("/clients/login", controller.loginHandler)
		r.ServeHTTP(rr, req)

		assert.Equal(t, 400, rr.Code)
		assert.Contains(t, rr.Body.String(), "client id is required")
		assert.Contains(t, rr.Body.String(), "password is required")
	})
}

func TestAuthHandler(t *testing.T) {
	creds := auth.Credentials{
		ApiKey: "valid-api-key",
	}
	claims := map[string]any{"clientId": "client1", "typ": "at+jwt", "sub": "client1", "iss": "test-issuer"}

	t.Run("Successful API key auth", func(t *testing.T) {
		controller, mockRepo, config := setupTestController(t)
		mockRepo.On("VerifyAPIKey", creds.ApiKey, "test-realm", config).Return(claims, nil).Once()

		body, _ := json.Marshal(creds)
		req, _ := http.NewRequest("POST", "/clients/auth?realm=test-realm", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()
		r := chi.NewRouter()
		r.Post("/clients/auth", controller.authHandler)
		r.ServeHTTP(rr, req)

		assert.Equal(t, 200, rr.Code)
		var responseBody any
		if rr.Body.Len() > 0 {
			json.Unmarshal(rr.Body.Bytes(), &responseBody)
		}
		assert.Equal(t, claims, responseBody)
	})

	t.Run("Invalid API key", func(t *testing.T) {
		controller, mockRepo, config := setupTestController(t)
		mockRepo.On("VerifyAPIKey", creds.ApiKey, "test-realm", config).Return((map[string]any)(nil), errors.New("invalid key")).Once()

		body, _ := json.Marshal(creds)
		req, _ := http.NewRequest("POST", "/clients/auth?realm=test-realm", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()
		r := chi.NewRouter()
		r.Post("/clients/auth", controller.authHandler)
		r.ServeHTTP(rr, req)

		assert.Equal(t, 401, rr.Code)
		assert.Contains(t, rr.Body.String(), `"error":"Unauthorized"`)
		assert.Contains(t, rr.Body.String(), `"message":"invalid or expired API key"`)
	})

	t.Run("Invalid token", func(t *testing.T) {
		creds := auth.Credentials{
			AccessToken: "invalid token",
		}
		controller, _, _ := setupTestController(t)

		body, _ := json.Marshal(creds)
		req, _ := http.NewRequest("POST", "/clients/auth?realm=test-realm", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()
		r := chi.NewRouter()
		r.Post("/clients/auth", controller.authHandler)
		r.ServeHTTP(rr, req)

		assert.Equal(t, 401, rr.Code)
		assert.Contains(t, rr.Body.String(), `"error":"Unauthorized"`)
		assert.Contains(t, rr.Body.String(), `"message":"invalid or expired access token"`)
	})

	t.Run("Empty credentials", func(t *testing.T) {
		creds := auth.Credentials{
			AccessToken: "",
		}
		controller, _, _ := setupTestController(t)

		body, _ := json.Marshal(creds)
		req, _ := http.NewRequest("POST", "/clients/auth?realm=test-realm", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()
		r := chi.NewRouter()
		r.Post("/clients/auth", controller.authHandler)
		r.ServeHTTP(rr, req)

		assert.Equal(t, 400, rr.Code)
		assert.Contains(t, rr.Body.String(), `"message":"token is required for authentication"`)
	})

	t.Run("Invalid realm", func(t *testing.T) {
		controller, _, _ := setupTestController(t)
		body, _ := json.Marshal(creds)

		req, _ := http.NewRequest("POST", "/clients/auth?realm=invalid-realm", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()
		r := chi.NewRouter()
		r.Post("/clients/auth", controller.authHandler)
		r.ServeHTTP(rr, req)

		assert.Equal(t, 400, rr.Code)
		assert.Contains(t, rr.Body.String(), `"message":"unknown realm specified: invalid-realm"`)
	})
}

func TestRefreshHandler(t *testing.T) {
	tokenPair := setupTokenPair(t)
	newTokenPair := setupTokenPair(t)

	t.Run("Successful refresh", func(t *testing.T) {
		controller, mockRepo, config := setupTestController(t)
		mockRepo.On("RefreshToken", mock.Anything, "test-realm", config).Return(newTokenPair, nil).Once()

		body, _ := json.Marshal(*tokenPair)
		req, _ := http.NewRequest("POST", "/clients/refresh?realm=test-realm", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()
		r := chi.NewRouter()
		r.Post("/clients/refresh", controller.refreshHandler)
		r.ServeHTTP(rr, req)

		assert.Equal(t, 200, rr.Code)
		var responseBody auth.TokenPair
		if rr.Body.Len() > 0 {
			json.Unmarshal(rr.Body.Bytes(), &responseBody)
		}
		assert.Equal(t, *newTokenPair, responseBody)
	})

	t.Run("Missing refresh token", func(t *testing.T) {
		controller, _, _ := setupTestController(t)
		invalidToken := auth.TokenPair{}

		body, _ := json.Marshal(invalidToken)
		req, _ := http.NewRequest("POST", "/clients/refresh?realm=test-realm", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()
		r := chi.NewRouter()
		r.Post("/clients/refresh", controller.refreshHandler)
		r.ServeHTTP(rr, req)

		assert.Equal(t, 400, rr.Code)
		assert.Contains(t, rr.Body.String(), `"message":"refresh token is required"`)
	})

	t.Run("Refresh token reuse", func(t *testing.T) {
		controller, mockRepo, config := setupTestController(t)
		mockRepo.On("RefreshToken", mock.Anything, "test-realm", config).Return((*auth.TokenPair)(nil), errors.New("access denied - refresh token cannot be reused")).Once()

		body, _ := json.Marshal(*tokenPair)
		req, _ := http.NewRequest("POST", "/clients/refresh?realm=test-realm", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()
		r := chi.NewRouter()
		r.Post("/clients/refresh", controller.refreshHandler)
		r.ServeHTTP(rr, req)

		assert.Equal(t, 401, rr.Code)
		assert.Contains(t, rr.Body.String(), `"message":"refresh token cannot be reused"`)
	})

	t.Run("DB error", func(t *testing.T) {
		controller, mockRepo, config := setupTestController(t)
		mockRepo.On("RefreshToken", mock.Anything, "test-realm", config).Return((*auth.TokenPair)(nil), errors.New("Db error")).Once()

		body, _ := json.Marshal(*tokenPair)
		req, _ := http.NewRequest("POST", "/clients/refresh?realm=test-realm", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()
		r := chi.NewRouter()
		r.Post("/clients/refresh", controller.refreshHandler)
		r.ServeHTTP(rr, req)

		assert.Equal(t, 500, rr.Code)
		assert.Contains(t, rr.Body.String(), `"message":"failed to refresh token"`)
	})

	t.Run("Token verification failure", func(t *testing.T) {
		controller, mockRepo, config := setupTestController(t)
		mockRepo.On("RefreshToken", mock.Anything, "test-realm", config).Return(newTokenPair, nil).Once()

		tokenPair.RefreshToken = "invalid-refresh-token"
		body, _ := json.Marshal(*tokenPair)
		req, _ := http.NewRequest("POST", "/clients/refresh?realm=test-realm", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()
		r := chi.NewRouter()
		r.Post("/clients/refresh", controller.refreshHandler)
		r.ServeHTTP(rr, req)

		assert.Equal(t, 401, rr.Code)
		assert.Contains(t, rr.Body.String(), `"message":"invalid refresh token"`)
	})
}

func TestLogoutHandler(t *testing.T) {
	tokenPair := setupTokenPair(t)

	t.Run("Successful logout", func(t *testing.T) {
		controller, mockRepo, _ := setupTestController(t)
		mockRepo.On("LogoutClient", mock.Anything, "test-realm").Return(nil).Once()

		body, _ := json.Marshal(tokenPair)
		req, _ := http.NewRequest("POST", "/clients/logout?realm=test-realm", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()
		r := chi.NewRouter()
		r.Post("/clients/logout", controller.logoutHandler)
		r.ServeHTTP(rr, req)

		assert.Equal(t, 200, rr.Code)
		assert.Contains(t, rr.Body.String(), `"message":"OK"`)
	})

	t.Run("Missing refresh token", func(t *testing.T) {
		controller, _, _ := setupTestController(t)
		invalidToken := auth.TokenPair{}

		body, _ := json.Marshal(invalidToken)
		req, _ := http.NewRequest("POST", "/clients/logout?realm=test-realm", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()
		r := chi.NewRouter()
		r.Post("/clients/logout", controller.logoutHandler)
		r.ServeHTTP(rr, req)

		assert.Equal(t, 400, rr.Code)
		assert.Contains(t, rr.Body.String(), `"message":"refresh token is required"`)
	})

	t.Run("Logout failure", func(t *testing.T) {
		controller, mockRepo, _ := setupTestController(t)
		mockRepo.On("LogoutClient", mock.Anything, "test-realm").Return(errors.New("logout error")).Once()

		body, _ := json.Marshal(tokenPair)
		req, _ := http.NewRequest("POST", "/clients/logout?realm=test-realm", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()
		r := chi.NewRouter()
		r.Post("/clients/logout", controller.logoutHandler)
		r.ServeHTTP(rr, req)

		assert.Equal(t, 500, rr.Code)
	})

	t.Run("Token verification failure", func(t *testing.T) {
		controller, mockRepo, _ := setupTestController(t)
		mockRepo.On("LogoutClient", mock.Anything, "test-realm").Return(nil).Once()

		tokenPair.RefreshToken = "invalid-refresh-token"
		body, _ := json.Marshal(tokenPair)
		req, _ := http.NewRequest("POST", "/clients/logout?realm=test-realm", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()
		r := chi.NewRouter()
		r.Post("/clients/logout", controller.logoutHandler)
		r.ServeHTTP(rr, req)

		assert.Equal(t, 401, rr.Code)
		assert.Contains(t, rr.Body.String(), `"message":"invalid refresh token"`)
	})
}
