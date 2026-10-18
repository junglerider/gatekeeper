package app

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/go-chi/chi/v5"
	"github.com/jmoiron/sqlx"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// mock implementation of the Controller interface
type MockController struct {
	mock.Mock
}

func (m *MockController) RegisterRoutes(public chi.Router, protected chi.Router) {
	m.Called(public, protected)
}

// protection middleware rejecting every request
func denyAll(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
}

func TestInit(t *testing.T) {
	t.Setenv("MASTER_KEY", validMasterKey)
	withTempConfigDir(t, "config.yml", validConfigYAML("false"), func() {

		// Create a mock database
		db, mock, err := sqlmock.New()
		require.NoError(t, err)
		defer db.Close()

		// Create a mock connector
		mockConnector := func(driverName, dataSourceName string) (*sqlx.DB, error) {
			assert.Contains(t, dataSourceName, "parseTime=true")
			assert.Contains(t, dataSourceName, "clientFoundRows=true")
			assert.Equal(t, "mysql", driverName)
			return sqlx.NewDb(db, driverName), nil
		}

		// disable logger
		zerolog.SetGlobalLevel(zerolog.Disabled)

		// Initialize container
		container := Init(mockConnector)

		// check container
		assert.NotNil(t, container, "Container should not be nil")
		assert.NotNil(t, container.Config, "Container.Config should not be nil")
		assert.NotNil(t, container.DB, "Container.DB should not be nil")

		// Ensure no unexpected database interactions
		assert.NoError(t, mock.ExpectationsWereMet())

		// check config
		expectedConfig, _ := ReadConfig()
		assert.Equal(t, expectedConfig, container.Config, "Container.Config should match expected config")

		// check logger
		assert.NotEqual(t, zerolog.GlobalLevel(), zerolog.Disabled, "Logger should be enabled")

		// check database
		err = container.DB.Ping()
		assert.NoError(t, err, "Database ping should succeed")
	})
}

func TestRegisterRoutes(t *testing.T) {
	// Create a test container
	container := &Container{
		Config: &Config{
			Server: struct {
				Port           int    `yaml:"port"`
				LogLevel       string `yaml:"logLevel"`
				LogRequests    bool   `yaml:"logRequests"`
				PrettyPrint    bool   `yaml:"prettyPrint"`
				ApiKeyCacheTTL int    `yaml:"apiKeyCacheTTL"`
			}{
				Port:           8080,
				LogLevel:       "info",
				LogRequests:    false,
				PrettyPrint:    true,
				ApiKeyCacheTTL: 600,
			},
		},
	}
	// create a mock controller
	mockController := new(MockController)
	container.Controllers = []Controller{mockController}
	container.Protect = denyAll

	// set up expectations for the mock controller
	mockController.On("RegisterRoutes", mock.Anything, mock.Anything).Return()

	// create a test router
	handler := RegisterRoutes(container)

	// test /livez endpoint
	t.Run("Liveness Endpoint", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/livez", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code, "Liveness endpoint should return 200")
		assert.JSONEq(t, `{"status": "OK"}`, rr.Body.String(), "Liveness endpoint should return correct JSON")
	})

	// verify mock controller was called
	mockController.AssertExpectations(t)
}

func TestRegisterRoutes_Readiness(t *testing.T) {
	for _, test := range []struct {
		name       string
		pingErr    error
		wantStatus int
	}{
		{name: "ready", wantStatus: http.StatusOK},
		{name: "database unavailable", pingErr: fmt.Errorf("ping failed"), wantStatus: http.StatusServiceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
			require.NoError(t, err)
			defer db.Close()
			mock.ExpectPing().WillReturnError(test.pingErr)

			handler := RegisterRoutes(&Container{
				Config:  &Config{},
				DB:      sqlx.NewDb(db, "sqlmock"),
				Protect: denyAll,
			})
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
			assert.Equal(t, test.wantStatus, rr.Code)
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}

	t.Run("database not configured", func(t *testing.T) {
		handler := RegisterRoutes(&Container{Config: &Config{}, Protect: denyAll})
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
	})
}

func TestRegisterRoutes_LogRequestsDisabled(t *testing.T) {
	// Create a test container with LogRequests disabled.
	container := &Container{
		Config: &Config{
			Server: struct {
				Port           int    `yaml:"port"`
				LogLevel       string `yaml:"logLevel"`
				LogRequests    bool   `yaml:"logRequests"`
				PrettyPrint    bool   `yaml:"prettyPrint"`
				ApiKeyCacheTTL int    `yaml:"apiKeyCacheTTL"`
			}{
				Port:           8080,
				LogLevel:       "info",
				LogRequests:    false,
				PrettyPrint:    true,
				ApiKeyCacheTTL: 600,
			},
		},
	}

	// create a mock controller
	mockController := new(MockController)
	container.Controllers = []Controller{mockController}
	container.Protect = denyAll

	// set up expectations for the mock controller
	mockController.On("RegisterRoutes", mock.Anything, mock.Anything).Return()

	// create a test router
	handler := RegisterRoutes(container)

	// unknown routes should still be handled normally when request logging is disabled
	req := httptest.NewRequest(http.MethodGet, "/missing", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code, "unknown routes should return 404")
	mockController.AssertExpectations(t)
}

func TestStart_ServesRequestsAndShutsDownOnSignal(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	require.NoError(t, listener.Close())

	config := &Config{}
	config.Server.Port = port
	done := make(chan struct{})
	go func() {
		Start(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}), config)
		close(done)
	}()

	client := &http.Client{Timeout: 100 * time.Millisecond}
	started := assert.Eventually(t, func() bool {
		response, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d", port))
		if err != nil {
			return false
		}
		defer response.Body.Close()
		return response.StatusCode == http.StatusNoContent
	}, 2*time.Second, 10*time.Millisecond)

	process, err := os.FindProcess(os.Getpid())
	require.NoError(t, err)
	assert.NoError(t, process.Signal(syscall.SIGTERM))
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not shut down after SIGTERM")
	}
	assert.True(t, started, "server should serve a request before shutdown")
}

// registers one public and one protected route
type routeController struct{}

func (routeController) RegisterRoutes(public chi.Router, protected chi.Router) {
	ok := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }
	public.Post("/login", ok)
	protected.Get("/items", ok)
}

func TestRegisterRoutes_ProtectedGroup(t *testing.T) {
	for _, logRequests := range []bool{false, true} {
		container := &Container{
			Config:      &Config{},
			Controllers: []Controller{routeController{}},
			Protect:     denyAll,
		}
		container.Config.Server.LogRequests = logRequests
		handler := RegisterRoutes(container)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/login", nil))
		assert.Equal(t, http.StatusOK, rr.Code, "public route must bypass the protection middleware")

		rr = httptest.NewRecorder()
		handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/items", nil))
		assert.Equal(t, http.StatusUnauthorized, rr.Code, "protected route must run the protection middleware")
	}
}

func TestRegisterRoutes_RequiresProtect(t *testing.T) {
	assert.Panics(t, func() { RegisterRoutes(&Container{Config: &Config{}}) })
}
