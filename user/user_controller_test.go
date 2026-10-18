package user

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"junglerider/gatekeeper/app"
	"junglerider/gatekeeper/auth"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
)

type mockUserRepo struct {
	listUsersFunc    func(realm string, clientID *string, isActive *bool, expiry *time.Time) ([]UserPK, error)
	readUserFunc     func(u *UserPK) (*User, error)
	createUserFunc   func(user User) error
	updateUserFunc   func(u *UserPK, props map[string]any) (int64, error)
	deleteUserFunc   func(u *UserPK) (int64, error)
	loginUserFunc    func(login *User, config *app.Config) (*auth.TokenPair, error)
	refreshTokenFunc func(claims jwt.MapClaims, realm string, config *app.Config) (*auth.TokenPair, error)
	logoutUserFunc   func(claims jwt.MapClaims, realm string) error
	otpLoginFunc     func(realm string, login OTPLogin, config *app.Config) (*auth.TokenPair, error)
}

func (m *mockUserRepo) ListUsers(realm string, clientID *string, isActive *bool, expiry *time.Time) ([]UserPK, error) {
	return m.listUsersFunc(realm, clientID, isActive, expiry)
}

func (m *mockUserRepo) ReadUser(u *UserPK) (*User, error) {
	return m.readUserFunc(u)
}

func (m *mockUserRepo) CreateUser(user User) error {
	return m.createUserFunc(user)
}

func (m *mockUserRepo) UpdateUser(u *UserPK, props map[string]any) (int64, error) {
	return m.updateUserFunc(u, props)
}

func (m *mockUserRepo) DeleteUser(u *UserPK) (int64, error) {
	return m.deleteUserFunc(u)
}

func (m *mockUserRepo) LoginUser(login *User, config *app.Config) (*auth.TokenPair, error) {
	return m.loginUserFunc(login, config)
}

func (m *mockUserRepo) RefreshToken(claims jwt.MapClaims, realm string, config *app.Config) (*auth.TokenPair, error) {
	return m.refreshTokenFunc(claims, realm, config)
}

func (m *mockUserRepo) LogoutUser(claims jwt.MapClaims, realm string) error {
	return m.logoutUserFunc(claims, realm)
}

func (m *mockUserRepo) OTPLogin(realm string, login OTPLogin, config *app.Config) (*auth.TokenPair, error) {
	return m.otpLoginFunc(realm, login, config)
}

// helper function to create a pointer to a value
func PtrFacade[T any](val T) *T {
	return &val
}

// creates a valid token pair for testing
func setupTokenPair(t *testing.T) *auth.TokenPair {
	user := User{
		ClientID: "client1",
		Realm:    "test",
		Name:     "user1",
	}
	claims := map[string]any{}
	claims["sex"] = time.Now().Unix() + 600
	config := setupTestConfig()
	if tokenPair, _, err := auth.CreateTokenPair(&user, claims, *config); err != nil {
		t.Fatalf("failed to create token pair: %v", err)
		return nil
	} else {
		return tokenPair
	}
}

func setupTestConfig() *app.Config {
	signingPrivateKey, verificationPublicKey := testSigningKeys(3)
	return &app.Config{
		Realms: map[string]app.RealmConfig{
			"api": {
				SigningPrivateKey:     signingPrivateKey,
				VerificationPublicKey: verificationPublicKey,
				AccessTokenLifetime:   3600,
				RefreshTokenLifetime:  86400,
				SessionMaxLifetime:    604800,
				Claims:                map[string]any{},
			},
			"test": {
				SigningPrivateKey:     signingPrivateKey,
				VerificationPublicKey: verificationPublicKey,
				AccessTokenLifetime:   3600,
				RefreshTokenLifetime:  86400,
				SessionMaxLifetime:    604800,
				Claims:                map[string]any{},
			},
		},
	}
}

func addChiParams(req *http.Request, params map[string]string) *http.Request {
	ctx := chi.NewRouteContext()
	for k, v := range params {
		if k != "realm" {
			ctx.URLParams.Add(k, v)
		}
	}
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, ctx))
}

func TestListHandler(t *testing.T) {
	config := setupTestConfig()
	mock := &mockUserRepo{}
	c := &Controller{
		BaseController: &app.BaseController{Config: config},
		repo:           mock,
	}

	t.Run("DefaultRealm", func(t *testing.T) {
		mock.listUsersFunc = func(realm string, clientID *string, isActive *bool, expiry *time.Time) ([]UserPK, error) {
			if realm != "api" {
				t.Errorf("expected realm api, got %s", realm)
			}
			return []UserPK{}, nil
		}
		req := httptest.NewRequest("GET", "/users", nil)
		w := httptest.NewRecorder()
		c.listHandler(w, req)
		if w.Code != 200 {
			t.Errorf("expected status 200, got %d", w.Code)
		}
	})

	t.Run("ExpiryFilter", func(t *testing.T) {
		expectedExpiry := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
		mock.listUsersFunc = func(_ string, _ *string, _ *bool, expiry *time.Time) ([]UserPK, error) {
			if expiry == nil || !expiry.Equal(expectedExpiry) {
				t.Errorf("expected expiry %v, got %v", expectedExpiry, expiry)
			}
			return []UserPK{}, nil
		}
		req := httptest.NewRequest("GET", "/users?realm=test&expiry=2026-10-11T00:00:00Z", nil)
		req = addChiParams(req, map[string]string{"realm": "test"})
		w := httptest.NewRecorder()
		c.listHandler(w, req)
		if w.Code != 200 {
			t.Errorf("expected status 200, got %d", w.Code)
		}
	})

	t.Run("InvalidRealm", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/users?realm=invalid", nil)
		req = addChiParams(req, map[string]string{"realm": "invalid"})
		w := httptest.NewRecorder()
		c.listHandler(w, req)
		if w.Code != 400 {
			t.Errorf("expected status 400, got %d", w.Code)
		}
	})

	t.Run("InvalidClientID", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/users?realm=test&clientId=verylongclientidmorethan16", nil)
		req = addChiParams(req, map[string]string{"realm": "test"})
		w := httptest.NewRecorder()
		c.listHandler(w, req)
		if w.Code != 400 {
			t.Errorf("expected status 400, got %d", w.Code)
		}
	})

	t.Run("RepoError", func(t *testing.T) {
		mock.listUsersFunc = func(realm string, clientID *string, isActive *bool, expiry *time.Time) ([]UserPK, error) {
			return nil, errors.New("repo error")
		}
		req := httptest.NewRequest("GET", "/users?realm=test", nil)
		req = addChiParams(req, map[string]string{"realm": "test"})
		w := httptest.NewRecorder()
		c.listHandler(w, req)
		if w.Code != 500 {
			t.Errorf("expected status 500, got %d", w.Code)
		}
	})

	t.Run("Success", func(t *testing.T) {
		expectedUsers := []UserPK{{Realm: "test", ClientID: "client1", Name: "user1"}}
		mock.listUsersFunc = func(realm string, clientID *string, isActive *bool, expiry *time.Time) ([]UserPK, error) {
			return expectedUsers, nil
		}
		req := httptest.NewRequest("GET", "/users?realm=test", nil)
		req = addChiParams(req, map[string]string{"realm": "test"})
		w := httptest.NewRecorder()
		c.listHandler(w, req)
		if w.Code != 200 {
			t.Errorf("expected status 200, got %d", w.Code)
		}
		var got []UserPK
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Error(err)
		}
		if len(got) != len(expectedUsers) {
			t.Errorf("expected %d users, got %d", len(expectedUsers), len(got))
		}
	})
}

func TestReadHandler(t *testing.T) {
	config := setupTestConfig()
	mock := &mockUserRepo{}
	c := &Controller{
		BaseController: &app.BaseController{Config: config},
		repo:           mock,
	}

	t.Run("InvalidParams", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/users/client1/user1?realm=invalid", nil)
		req = addChiParams(req, map[string]string{"realm": "invalid", "clientId": "client1", "name": "user1"})
		w := httptest.NewRecorder()
		c.readHandler(w, req)
		if w.Code != 400 {
			t.Errorf("expected status 400, got %d", w.Code)
		}
	})

	t.Run("NotFound", func(t *testing.T) {
		mock.readUserFunc = func(u *UserPK) (*User, error) {
			return nil, sql.ErrNoRows
		}
		req := httptest.NewRequest("GET", "/users/client1/user1?realm=test", nil)
		req = addChiParams(req, map[string]string{"realm": "test", "clientId": "client1", "name": "user1"})
		w := httptest.NewRecorder()
		c.readHandler(w, req)
		if w.Code != 404 {
			t.Errorf("expected status 404, got %d", w.Code)
		}
	})

	t.Run("RepoError", func(t *testing.T) {
		mock.readUserFunc = func(u *UserPK) (*User, error) {
			return nil, errors.New("repo error")
		}
		req := httptest.NewRequest("GET", "/users/client1/user1?realm=test", nil)
		req = addChiParams(req, map[string]string{"realm": "test", "clientId": "client1", "name": "user1"})
		w := httptest.NewRecorder()
		c.readHandler(w, req)
		if w.Code != 500 {
			t.Errorf("expected status 500, got %d", w.Code)
		}
	})

	t.Run("Success", func(t *testing.T) {
		expectedUser := &User{ClientID: "client1", Realm: "test", Name: "user1", Password: nil, OTPSecret: nil}
		mock.readUserFunc = func(u *UserPK) (*User, error) {
			return expectedUser, nil
		}
		req := httptest.NewRequest("GET", "/users/client1/user1?realm=test", nil)
		req = addChiParams(req, map[string]string{"realm": "test", "clientId": "client1", "name": "user1"})
		w := httptest.NewRecorder()
		c.readHandler(w, req)
		if w.Code != 200 {
			t.Errorf("expected status 200, got %d", w.Code)
		}
		var got User
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Error(err)
		}
		if got.ClientID != expectedUser.ClientID {
			t.Errorf("expected clientID %s, got %s", expectedUser.ClientID, got.ClientID)
		}
	})
}

func TestCreateHandler(t *testing.T) {
	config := setupTestConfig()
	mock := &mockUserRepo{}
	c := &Controller{
		BaseController: &app.BaseController{Config: config},
		repo:           mock,
	}

	t.Run("InvalidJSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/users", bytes.NewReader([]byte("invalid")))
		req = addChiParams(req, map[string]string{"realm": "test"})
		w := httptest.NewRecorder()
		c.createHandler(w, req)
		if w.Code != 400 {
			t.Errorf("expected status 400, got %d", w.Code)
		}
	})

	t.Run("InvalidFields", func(t *testing.T) {
		user := User{Realm: "test", ClientID: "", Name: "", Password: PtrFacade("short")}
		body, _ := json.Marshal(user)
		req := httptest.NewRequest("POST", "/users", bytes.NewReader(body))
		req = addChiParams(req, map[string]string{"realm": "test"})
		w := httptest.NewRecorder()
		c.createHandler(w, req)
		if w.Code != 400 {
			t.Errorf("expected status 400, got %d", w.Code)
		}
	})

	t.Run("RealmMinimumPasswordLength", func(t *testing.T) {
		config := setupTestConfig()
		realmConfig := config.Realms["test"]
		realmConfig.MinPasswordLength = 14
		config.Realms["test"] = realmConfig
		mock := &mockUserRepo{}
		c := &Controller{BaseController: &app.BaseController{Config: config}, repo: mock}
		user := User{Realm: "test", ClientID: "client1", Name: "user1", Password: PtrFacade("password123")}
		body, _ := json.Marshal(user)
		req := httptest.NewRequest("POST", "/users", bytes.NewReader(body))
		w := httptest.NewRecorder()
		c.createHandler(w, req)

		if w.Code != 400 {
			t.Errorf("expected status 400, got %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), "password must be at least 14 characters") {
			t.Errorf("expected realm minimum password error, got %s", w.Body.String())
		}
	})

	t.Run("PasswordBelowMinimumLength", func(t *testing.T) {
		repoCalled := false
		mock.createUserFunc = func(user User) error {
			repoCalled = true
			return nil
		}
		user := User{Realm: "test", ClientID: "client1", Name: "user1", Password: PtrFacade("short")}
		body, _ := json.Marshal(user)
		req := httptest.NewRequest("POST", "/users", bytes.NewReader(body))
		req = addChiParams(req, map[string]string{"realm": "test"})
		w := httptest.NewRecorder()
		c.createHandler(w, req)
		if w.Code != 400 {
			t.Errorf("expected status 400, got %d", w.Code)
		}
		if repoCalled {
			t.Error("expected repository not to be called")
		}
	})

	t.Run("OTPSecretBelowMinimumLength", func(t *testing.T) {
		repoCalled := false
		mock.createUserFunc = func(user User) error {
			repoCalled = true
			return nil
		}
		user := User{
			Realm:     "test",
			ClientID:  "client1",
			Name:      "user1",
			Password:  PtrFacade("password123"),
			OTPSecret: PtrFacade("shortsecret"),
		}
		body, _ := json.Marshal(user)
		req := httptest.NewRequest("POST", "/users", bytes.NewReader(body))
		req = addChiParams(req, map[string]string{"realm": "test"})
		w := httptest.NewRecorder()
		c.createHandler(w, req)
		if w.Code != 400 {
			t.Errorf("expected status 400, got %d", w.Code)
		}
		if repoCalled {
			t.Error("expected repository not to be called")
		}
	})

	t.Run("DuplicateError", func(t *testing.T) {
		mock.createUserFunc = func(user User) error {
			return errors.New("Duplicate entry")
		}
		user := User{Realm: "test", ClientID: "client1", Name: "user1", Password: PtrFacade("password123")}
		body, _ := json.Marshal(user)
		req := httptest.NewRequest("POST", "/users", bytes.NewReader(body))
		req = addChiParams(req, map[string]string{"realm": "test"})
		w := httptest.NewRecorder()
		c.createHandler(w, req)
		if w.Code != 409 {
			t.Errorf("expected status 409, got %d", w.Code)
		}
	})

	t.Run("RepoError", func(t *testing.T) {
		mock.createUserFunc = func(user User) error {
			return errors.New("repo error")
		}
		user := User{Realm: "test", ClientID: "client1", Name: "user1", Password: PtrFacade("password123")}
		body, _ := json.Marshal(user)
		req := httptest.NewRequest("POST", "/users", bytes.NewReader(body))
		req = addChiParams(req, map[string]string{"realm": "test"})
		w := httptest.NewRecorder()
		c.createHandler(w, req)
		if w.Code != 500 {
			t.Errorf("expected status 500, got %d", w.Code)
		}
	})

	t.Run("Success", func(t *testing.T) {
		var createdRealm string
		mock.createUserFunc = func(user User) error {
			createdRealm = user.Realm
			return nil
		}
		user := User{Realm: "test", ClientID: "client1", Name: "user1", Password: PtrFacade("password123")}
		body, _ := json.Marshal(user)
		req := httptest.NewRequest("POST", "/users?realm=internal", bytes.NewReader(body))
		req = addChiParams(req, map[string]string{"realm": "test"})
		w := httptest.NewRecorder()
		c.createHandler(w, req)
		if w.Code != 201 {
			t.Errorf("expected status 201, got %d", w.Code)
		}
		if createdRealm != "test" {
			t.Errorf("expected body realm test to be used, got %s", createdRealm)
		}
	})
}

func TestUpdateHandler(t *testing.T) {
	config := setupTestConfig()
	mock := &mockUserRepo{}
	c := &Controller{
		BaseController: &app.BaseController{Config: config},
		repo:           mock,
	}

	t.Run("InvalidParams", func(t *testing.T) {
		req := httptest.NewRequest("PATCH", "/users/client1/user1?realm=invalid", bytes.NewReader([]byte("{}")))
		req = addChiParams(req, map[string]string{"realm": "invalid", "clientId": "client1", "name": "user1"})
		w := httptest.NewRecorder()
		c.updateHandler(w, req)
		if w.Code != 400 {
			t.Errorf("expected status 400, got %d", w.Code)
		}
	})

	t.Run("InvalidJSON", func(t *testing.T) {
		req := httptest.NewRequest("PATCH", "/users/client1/user1?realm=test", bytes.NewReader([]byte("invalid")))
		req = addChiParams(req, map[string]string{"realm": "test", "clientId": "client1", "name": "user1"})
		w := httptest.NewRecorder()
		c.updateHandler(w, req)
		if w.Code != 400 {
			t.Errorf("expected status 400, got %d", w.Code)
		}
	})

	t.Run("NoProps", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{})
		req := httptest.NewRequest("PATCH", "/users/client1/user1?realm=test", bytes.NewReader(body))
		req = addChiParams(req, map[string]string{"realm": "test", "clientId": "client1", "name": "user1"})
		w := httptest.NewRecorder()
		c.updateHandler(w, req)
		if w.Code != 400 {
			t.Errorf("expected status 400, got %d", w.Code)
		}
	})

	t.Run("PasswordExpiryUpdate", func(t *testing.T) {
		expiry := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
		mock := &mockUserRepo{
			updateUserFunc: func(_ *UserPK, props map[string]any) (int64, error) {
				got, ok := props["pwd_expiry"].(time.Time)
				if !ok || !got.Equal(expiry) {
					t.Errorf("expected pwd_expiry %v, got %v", expiry, props["pwd_expiry"])
				}
				return 1, nil
			},
		}
		c := &Controller{BaseController: &app.BaseController{Config: config}, repo: mock}
		body, _ := json.Marshal(map[string]any{"pwdExpiry": expiry.Format(time.RFC3339Nano)})
		req := httptest.NewRequest("PATCH", "/users/client1/user1?realm=test", bytes.NewReader(body))
		req = addChiParams(req, map[string]string{"realm": "test", "clientId": "client1", "name": "user1"})
		w := httptest.NewRecorder()
		c.updateHandler(w, req)
		if w.Code != 204 {
			t.Errorf("expected status 204, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("PasswordBelowMinimumLength", func(t *testing.T) {
		repoCalled := false
		mock.updateUserFunc = func(u *UserPK, props map[string]any) (int64, error) {
			repoCalled = true
			return 1, nil
		}
		body, _ := json.Marshal(map[string]any{"password": "short"})
		req := httptest.NewRequest("PATCH", "/users/client1/user1?realm=test", bytes.NewReader(body))
		req = addChiParams(req, map[string]string{"realm": "test", "clientId": "client1", "name": "user1"})
		w := httptest.NewRecorder()
		c.updateHandler(w, req)
		if w.Code != 400 {
			t.Errorf("expected status 400, got %d", w.Code)
		}
		if repoCalled {
			t.Error("expected repository not to be called")
		}
	})

	t.Run("RealmMinimumPasswordLength", func(t *testing.T) {
		config := setupTestConfig()
		realmConfig := config.Realms["test"]
		realmConfig.MinPasswordLength = 14
		config.Realms["test"] = realmConfig
		repoCalled := false
		mock := &mockUserRepo{
			updateUserFunc: func(u *UserPK, props map[string]any) (int64, error) {
				repoCalled = true
				return 1, nil
			},
		}
		c := &Controller{BaseController: &app.BaseController{Config: config}, repo: mock}
		body, _ := json.Marshal(map[string]any{"password": "password123"})
		req := httptest.NewRequest("PATCH", "/users/client1/user1?realm=test", bytes.NewReader(body))
		req = addChiParams(req, map[string]string{"clientId": "client1", "name": "user1"})
		w := httptest.NewRecorder()
		c.updateHandler(w, req)

		if w.Code != 400 {
			t.Errorf("expected status 400, got %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), "password must be at least 14 characters") {
			t.Errorf("expected realm minimum password error, got %s", w.Body.String())
		}
		if repoCalled {
			t.Error("expected repository not to be called")
		}
	})

	t.Run("OTPSecretBelowMinimumLength", func(t *testing.T) {
		repoCalled := false
		mock.updateUserFunc = func(u *UserPK, props map[string]any) (int64, error) {
			repoCalled = true
			return 1, nil
		}
		body, _ := json.Marshal(map[string]any{"otpSecret": "shortsecret"})
		req := httptest.NewRequest("PATCH", "/users/client1/user1?realm=test", bytes.NewReader(body))
		req = addChiParams(req, map[string]string{"realm": "test", "clientId": "client1", "name": "user1"})
		w := httptest.NewRecorder()
		c.updateHandler(w, req)
		if w.Code != 400 {
			t.Errorf("expected status 400, got %d", w.Code)
		}
		if repoCalled {
			t.Error("expected repository not to be called")
		}
	})

	t.Run("NotFound", func(t *testing.T) {
		mock.updateUserFunc = func(u *UserPK, props map[string]any) (int64, error) {
			return 0, nil
		}
		body, _ := json.Marshal(map[string]any{"isActive": true})
		req := httptest.NewRequest("PATCH", "/users/client1/user1?realm=test", bytes.NewReader(body))
		req = addChiParams(req, map[string]string{"realm": "test", "clientId": "client1", "name": "user1"})
		w := httptest.NewRecorder()
		c.updateHandler(w, req)
		if w.Code != 404 {
			t.Errorf("expected status 404, got %d", w.Code)
		}
	})

	t.Run("RepoError", func(t *testing.T) {
		mock.updateUserFunc = func(u *UserPK, props map[string]any) (int64, error) {
			return 0, errors.New("repo error")
		}
		body, _ := json.Marshal(map[string]any{"isActive": true})
		req := httptest.NewRequest("PATCH", "/users/client1/user1?realm=test", bytes.NewReader(body))
		req = addChiParams(req, map[string]string{"realm": "test", "clientId": "client1", "name": "user1"})
		w := httptest.NewRecorder()
		c.updateHandler(w, req)
		if w.Code != 500 {
			t.Errorf("expected status 500, got %d", w.Code)
		}
	})

	t.Run("Success", func(t *testing.T) {
		mock.updateUserFunc = func(u *UserPK, props map[string]any) (int64, error) {
			return 1, nil
		}
		body, _ := json.Marshal(map[string]any{"isActive": true})
		req := httptest.NewRequest("PATCH", "/users/client1/user1?realm=test", bytes.NewReader(body))
		req = addChiParams(req, map[string]string{"realm": "test", "clientId": "client1", "name": "user1"})
		w := httptest.NewRecorder()
		c.updateHandler(w, req)
		if w.Code != 204 {
			t.Errorf("expected status 204, got %d", w.Code)
		}
	})

	t.Run("AccessJSONIsPassedAsString", func(t *testing.T) {
		mock.updateUserFunc = func(u *UserPK, props map[string]any) (int64, error) {
			if access, ok := props["access"].(string); !ok || access != `{"canRead":true}` {
				t.Errorf("expected JSON access string, got %#v", props["access"])
			}
			return 1, nil
		}
		body, _ := json.Marshal(map[string]any{"access": map[string]any{"canRead": true}})
		req := httptest.NewRequest("PATCH", "/users/client1/user1?realm=test", bytes.NewReader(body))
		req = addChiParams(req, map[string]string{"realm": "test", "clientId": "client1", "name": "user1"})
		w := httptest.NewRecorder()
		c.updateHandler(w, req)
		if w.Code != 204 {
			t.Errorf("expected status 204, got %d", w.Code)
		}
	})
}

func TestDeleteHandler(t *testing.T) {
	config := setupTestConfig()
	mock := &mockUserRepo{}
	c := &Controller{
		BaseController: &app.BaseController{Config: config},
		repo:           mock,
	}

	t.Run("InvalidParams", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/users/client1/user1?realm=invalid", nil)
		req = addChiParams(req, map[string]string{"realm": "invalid", "clientId": "client1", "name": "user1"})
		w := httptest.NewRecorder()
		c.deleteHandler(w, req)
		if w.Code != 400 {
			t.Errorf("expected status 400, got %d", w.Code)
		}
	})

	t.Run("NotFound", func(t *testing.T) {
		mock.deleteUserFunc = func(u *UserPK) (int64, error) {
			return 0, nil
		}
		req := httptest.NewRequest("DELETE", "/users/client1/user1?realm=test", nil)
		req = addChiParams(req, map[string]string{"realm": "test", "clientId": "client1", "name": "user1"})
		w := httptest.NewRecorder()
		c.deleteHandler(w, req)
		if w.Code != 404 {
			t.Errorf("expected status 404, got %d", w.Code)
		}
	})

	t.Run("RepoError", func(t *testing.T) {
		mock.deleteUserFunc = func(u *UserPK) (int64, error) {
			return 0, errors.New("repo error")
		}
		req := httptest.NewRequest("DELETE", "/users/client1/user1?realm=test", nil)
		req = addChiParams(req, map[string]string{"realm": "test", "clientId": "client1", "name": "user1"})
		w := httptest.NewRecorder()
		c.deleteHandler(w, req)
		if w.Code != 500 {
			t.Errorf("expected status 500, got %d", w.Code)
		}
	})

	t.Run("Success", func(t *testing.T) {
		mock.deleteUserFunc = func(u *UserPK) (int64, error) {
			return 1, nil
		}
		req := httptest.NewRequest("DELETE", "/users/client1/user1?realm=test", nil)
		req = addChiParams(req, map[string]string{"realm": "test", "clientId": "user1", "name": "user1"})
		w := httptest.NewRecorder()
		c.deleteHandler(w, req)
		if w.Code != 204 {
			t.Errorf("expected status 204, got %d", w.Code)
		}
	})
}

func TestLoginHandler(t *testing.T) {
	config := setupTestConfig()
	mock := &mockUserRepo{}
	c := &Controller{
		BaseController: &app.BaseController{Config: config},
		repo:           mock,
	}

	t.Run("InvalidJSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/users/login?realm=test", bytes.NewReader([]byte("invalid")))
		req = addChiParams(req, map[string]string{"realm": "test"})
		w := httptest.NewRecorder()
		c.loginHandler(w, req)
		if w.Code != 400 {
			t.Errorf("expected status 400, got %d", w.Code)
		}
	})

	t.Run("InvalidFields", func(t *testing.T) {
		user := User{ClientID: "", Name: "", Password: nil}
		body, _ := json.Marshal(user)
		req := httptest.NewRequest("POST", "/users/login?realm=test", bytes.NewReader(body))
		req = addChiParams(req, map[string]string{"realm": "test"})
		w := httptest.NewRecorder()
		c.loginHandler(w, req)
		if w.Code != 400 {
			t.Errorf("expected status 400, got %d", w.Code)
		}
	})

	t.Run("AccessDenied", func(t *testing.T) {
		mock.loginUserFunc = func(login *User, config *app.Config) (*auth.TokenPair, error) {
			return nil, errors.New("access denied")
		}
		user := User{ClientID: "client1", Name: "user1", Password: PtrFacade("password123")}
		body, _ := json.Marshal(user)
		req := httptest.NewRequest("POST", "/users/login?realm=test", bytes.NewReader(body))
		req = addChiParams(req, map[string]string{"realm": "test"})
		w := httptest.NewRecorder()
		c.loginHandler(w, req)
		if w.Code != 401 {
			t.Errorf("expected status 401, got %d", w.Code)
		}
	})

	t.Run("UnknownUser", func(t *testing.T) {
		mock.loginUserFunc = func(login *User, config *app.Config) (*auth.TokenPair, error) {
			return nil, fmt.Errorf("%w: user is not known", errCredentialsDenied)
		}
		body, _ := json.Marshal(User{ClientID: "client1", Name: "missing", Password: PtrFacade("password123")})
		req := httptest.NewRequest("POST", "/users/login?realm=test", bytes.NewReader(body))
		req = addChiParams(req, map[string]string{"realm": "test"})
		w := httptest.NewRecorder()
		c.loginHandler(w, req)
		if w.Code != 401 {
			t.Errorf("expected status 401, got %d", w.Code)
		}
	})

	t.Run("InvalidPassword", func(t *testing.T) {
		mock.loginUserFunc = func(login *User, config *app.Config) (*auth.TokenPair, error) {
			return nil, fmt.Errorf("%w: password invalid", errCredentialsDenied)
		}
		body, _ := json.Marshal(User{ClientID: "client1", Name: "user1", Password: PtrFacade("wrongpassword")})
		req := httptest.NewRequest("POST", "/users/login?realm=test", bytes.NewReader(body))
		req = addChiParams(req, map[string]string{"realm": "test"})
		w := httptest.NewRecorder()
		c.loginHandler(w, req)
		if w.Code != 401 {
			t.Errorf("expected status 401, got %d", w.Code)
		}
	})

	t.Run("ExpiredPassword", func(t *testing.T) {
		mock.loginUserFunc = func(login *User, config *app.Config) (*auth.TokenPair, error) {
			return nil, errPasswordExpired
		}
		user := User{ClientID: "client1", Name: "user1", Password: PtrFacade("password123")}
		body, _ := json.Marshal(user)
		req := httptest.NewRequest("POST", "/users/login?realm=test", bytes.NewReader(body))
		req = addChiParams(req, map[string]string{"realm": "test"})
		w := httptest.NewRecorder()
		c.loginHandler(w, req)
		if w.Code != 401 {
			t.Errorf("expected status 401, got %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), `"message":"password expired"`) {
			t.Errorf("expected expiry message, got %s", w.Body.String())
		}
	})

	t.Run("RepoError", func(t *testing.T) {
		mock.loginUserFunc = func(login *User, config *app.Config) (*auth.TokenPair, error) {
			return nil, errors.New("repo error")
		}
		user := User{ClientID: "client1", Name: "user1", Password: PtrFacade("password123")}
		body, _ := json.Marshal(user)
		req := httptest.NewRequest("POST", "/users/login?realm=test", bytes.NewReader(body))
		req = addChiParams(req, map[string]string{"realm": "test"})
		w := httptest.NewRecorder()
		c.loginHandler(w, req)
		if w.Code != 500 {
			t.Errorf("expected status 500, got %d", w.Code)
		}
	})

	t.Run("Success", func(t *testing.T) {
		mock.loginUserFunc = func(login *User, config *app.Config) (*auth.TokenPair, error) {
			return &auth.TokenPair{AccessToken: "access", RefreshToken: "refresh"}, nil
		}
		user := User{ClientID: "client1", Name: "user1", Password: PtrFacade("password123")}
		body, _ := json.Marshal(user)
		req := httptest.NewRequest("POST", "/users/login?realm=test", bytes.NewReader(body))
		req = addChiParams(req, map[string]string{"realm": "test"})
		w := httptest.NewRecorder()
		c.loginHandler(w, req)
		if w.Code != 200 {
			t.Errorf("expected status 200, got %d", w.Code)
		}
	})

	t.Run("ChallengeResponseContainsOnlyAccessToken", func(t *testing.T) {
		mock.loginUserFunc = func(login *User, config *app.Config) (*auth.TokenPair, error) {
			return &auth.TokenPair{AccessToken: "challenge"}, nil
		}
		user := User{ClientID: "client1", Name: "user1", Password: PtrFacade("password123")}
		body, _ := json.Marshal(user)
		req := httptest.NewRequest("POST", "/users/login?realm=test", bytes.NewReader(body))
		req = addChiParams(req, map[string]string{"realm": "test"})
		w := httptest.NewRecorder()
		c.loginHandler(w, req)

		var response map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatalf("could not decode challenge response: %v", err)
		}
		if w.Code != 200 || len(response) != 1 || response["accessToken"] != "challenge" {
			t.Errorf("expected challenge-only response, got status %d and body %s", w.Code, w.Body.String())
		}
	})
}

func TestAuthHandler(t *testing.T) {
	config := setupTestConfig()
	mock := &mockUserRepo{}
	c := &Controller{
		BaseController: &app.BaseController{Config: config},
		repo:           mock,
	}

	t.Run("InvalidJSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/users/auth?realm=test", bytes.NewReader([]byte("invalid")))
		req = addChiParams(req, map[string]string{"realm": "test"})
		w := httptest.NewRecorder()
		c.authHandler(w, req)
		if w.Code != 400 {
			t.Errorf("expected status 400, got %d", w.Code)
		}
	})

	t.Run("NoToken", func(t *testing.T) {
		creds := auth.Credentials{AccessToken: ""}
		body, _ := json.Marshal(creds)
		req := httptest.NewRequest("POST", "/users/auth?realm=test", bytes.NewReader(body))
		req = addChiParams(req, map[string]string{"realm": "test"})
		w := httptest.NewRecorder()
		c.authHandler(w, req)
		if w.Code != 400 {
			t.Errorf("expected status 400, got %d", w.Code)
		}
	})

	t.Run("InvalidToken", func(t *testing.T) {
		creds := auth.Credentials{AccessToken: "invalid"}
		body, _ := json.Marshal(creds)
		req := httptest.NewRequest("POST", "/users/auth?realm=test", bytes.NewReader(body))
		req = addChiParams(req, map[string]string{"realm": "test"})
		w := httptest.NewRecorder()
		c.authHandler(w, req)
		if w.Code != 401 {
			t.Errorf("expected status 401, got %d", w.Code)
		}
	})

	t.Run("Success", func(t *testing.T) {
		tokenPair := setupTokenPair(t)
		creds := auth.Credentials{AccessToken: tokenPair.AccessToken, RefreshToken: tokenPair.RefreshToken}
		body, _ := json.Marshal(creds)
		req := httptest.NewRequest("POST", "/users/auth?realm=test", bytes.NewReader(body))
		req = addChiParams(req, map[string]string{"realm": "test"})
		w := httptest.NewRecorder()
		c.authHandler(w, req)
		if w.Code != 200 {
			t.Errorf("expected status 200, got %d", w.Code)
		}
	})
}

func TestRefreshHandler(t *testing.T) {
	config := setupTestConfig()
	mock := &mockUserRepo{}
	c := &Controller{
		BaseController: &app.BaseController{Config: config},
		repo:           mock,
	}

	t.Run("InvalidJSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/users/refresh?realm=test", bytes.NewReader([]byte("invalid")))
		req = addChiParams(req, map[string]string{"realm": "test"})
		w := httptest.NewRecorder()
		c.refreshHandler(w, req)
		if w.Code != 400 {
			t.Errorf("expected status 400, got %d", w.Code)
		}
	})

	t.Run("NoRefreshToken", func(t *testing.T) {
		tok := auth.TokenPair{RefreshToken: ""}
		body, _ := json.Marshal(tok)
		req := httptest.NewRequest("POST", "/users/refresh?realm=test", bytes.NewReader(body))
		req = addChiParams(req, map[string]string{"realm": "test"})
		w := httptest.NewRecorder()
		c.refreshHandler(w, req)
		if w.Code != 400 {
			t.Errorf("expected status 400, got %d", w.Code)
		}
	})

	t.Run("InvalidToken", func(t *testing.T) {
		tok := auth.TokenPair{RefreshToken: "invalid"}
		body, _ := json.Marshal(tok)
		req := httptest.NewRequest("POST", "/users/refresh?realm=test", bytes.NewReader(body))
		req = addChiParams(req, map[string]string{"realm": "test"})
		w := httptest.NewRecorder()
		c.refreshHandler(w, req)
		if w.Code != 401 {
			t.Errorf("expected status 401, got %d", w.Code)
		}
	})

	t.Run("AccessDenied", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"typ": "rt+jwt"})
		signed, _ := token.SignedString([]byte("secretkey"))
		tok := auth.TokenPair{RefreshToken: signed}
		body, _ := json.Marshal(tok)
		mock.refreshTokenFunc = func(claims jwt.MapClaims, realm string, config *app.Config) (*auth.TokenPair, error) {
			return nil, errors.New("access denied")
		}
		req := httptest.NewRequest("POST", "/users/refresh?realm=test", bytes.NewReader(body))
		req = addChiParams(req, map[string]string{"realm": "test"})
		w := httptest.NewRecorder()
		c.refreshHandler(w, req)
		if w.Code != 401 {
			t.Errorf("expected status 401, got %d", w.Code)
		}
	})

	t.Run("RefreshTokenReuse", func(t *testing.T) {
		tokenPair := setupTokenPair(t)
		body, _ := json.Marshal(tokenPair)
		mock.refreshTokenFunc = func(claims jwt.MapClaims, realm string, config *app.Config) (*auth.TokenPair, error) {
			return nil, errors.New("access denied - refresh token cannot be reused")
		}
		req := httptest.NewRequest("POST", "/users/refresh?realm=test", bytes.NewReader(body))
		req = addChiParams(req, map[string]string{"realm": "test"})
		w := httptest.NewRecorder()
		c.refreshHandler(w, req)
		if w.Code != 401 {
			t.Fatalf("expected status 401, got %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), "\"message\":\"refresh token cannot be reused\"") {
			t.Fatalf("expected reuse message, got %s", w.Body.String())
		}
	})

	t.Run("RepoError", func(t *testing.T) {
		tokenPair := setupTokenPair(t)
		body, _ := json.Marshal(tokenPair)
		mock.refreshTokenFunc = func(claims jwt.MapClaims, realm string, config *app.Config) (*auth.TokenPair, error) {
			return nil, errors.New("repo error")
		}
		req := httptest.NewRequest("POST", "/users/refresh?realm=test", bytes.NewReader(body))
		req = addChiParams(req, map[string]string{"realm": "test"})
		w := httptest.NewRecorder()
		c.refreshHandler(w, req)
		if w.Code != 500 {
			t.Errorf("expected status 500, got %d", w.Code)
		}
	})

	t.Run("Success", func(t *testing.T) {
		tokenPair := setupTokenPair(t)
		body, _ := json.Marshal(tokenPair)
		mock.refreshTokenFunc = func(claims jwt.MapClaims, realm string, config *app.Config) (*auth.TokenPair, error) {
			return &auth.TokenPair{AccessToken: "newaccess", RefreshToken: "newrefresh"}, nil
		}
		req := httptest.NewRequest("POST", "/users/refresh?realm=test", bytes.NewReader(body))
		req = addChiParams(req, map[string]string{"realm": "test"})
		w := httptest.NewRecorder()
		c.refreshHandler(w, req)
		if w.Code != 200 {
			t.Errorf("expected status 200, got %d", w.Code)
		}
	})
}

func TestLogoutHandler(t *testing.T) {
	config := setupTestConfig()
	mock := &mockUserRepo{}
	c := &Controller{
		BaseController: &app.BaseController{Config: config},
		repo:           mock,
	}

	t.Run("InvalidJSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/users/logout?realm=test", bytes.NewReader([]byte("invalid")))
		req = addChiParams(req, map[string]string{"realm": "test"})
		w := httptest.NewRecorder()
		c.logoutHandler(w, req)
		if w.Code != 400 {
			t.Errorf("expected status 400, got %d", w.Code)
		}
	})

	t.Run("NoRefreshToken", func(t *testing.T) {
		tok := auth.TokenPair{RefreshToken: ""}
		body, _ := json.Marshal(tok)
		req := httptest.NewRequest("POST", "/users/logout?realm=test", bytes.NewReader(body))
		req = addChiParams(req, map[string]string{"realm": "test"})
		w := httptest.NewRecorder()
		c.logoutHandler(w, req)
		if w.Code != 400 {
			t.Errorf("expected status 400, got %d", w.Code)
		}
	})

	t.Run("InvalidToken", func(t *testing.T) {
		tok := auth.TokenPair{RefreshToken: "invalid"}
		body, _ := json.Marshal(tok)
		req := httptest.NewRequest("POST", "/users/logout?realm=test", bytes.NewReader(body))
		req = addChiParams(req, map[string]string{"realm": "test"})
		w := httptest.NewRecorder()
		c.logoutHandler(w, req)
		if w.Code != 401 {
			t.Errorf("expected status 401, got %d", w.Code)
		}
	})

	t.Run("RepoError", func(t *testing.T) {
		tokenPair := setupTokenPair(t)
		body, _ := json.Marshal(tokenPair)
		mock.logoutUserFunc = func(claims jwt.MapClaims, realm string) error {
			return errors.New("repo error")
		}
		req := httptest.NewRequest("POST", "/users/logout?realm=test", bytes.NewReader(body))
		req = addChiParams(req, map[string]string{"realm": "test"})
		w := httptest.NewRecorder()
		c.logoutHandler(w, req)
		if w.Code != 500 {
			t.Errorf("expected status 500, got %d", w.Code)
		}
	})

	t.Run("Success", func(t *testing.T) {
		tokenPair := setupTokenPair(t)
		body, _ := json.Marshal(tokenPair)
		mock.logoutUserFunc = func(claims jwt.MapClaims, realm string) error {
			return nil
		}
		req := httptest.NewRequest("POST", "/users/logout?realm=test", bytes.NewReader(body))
		req = addChiParams(req, map[string]string{"realm": "test"})
		w := httptest.NewRecorder()
		c.logoutHandler(w, req)
		if w.Code != 200 {
			t.Errorf("expected status 200, got %d", w.Code)
		}
	})
}

func TestOtpLoginHandler(t *testing.T) {
	config := setupTestConfig()
	mock := &mockUserRepo{}
	c := &Controller{
		BaseController: &app.BaseController{Config: config},
		repo:           mock,
	}
	challengeToken, err := auth.CreateChallengeToken(&User{ClientID: "client1", Realm: "test", Name: "user1"}, *config)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("InvalidJSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/users/otp/login?realm=test", bytes.NewReader([]byte("invalid")))
		req = addChiParams(req, map[string]string{"realm": "test"})
		w := httptest.NewRecorder()
		c.otpLoginHandler(w, req)
		if w.Code != 400 {
			t.Errorf("expected status 400, got %d", w.Code)
		}
	})

	t.Run("InvalidFields", func(t *testing.T) {
		login := OTPLogin{OTP: ""}
		body, _ := json.Marshal(login)
		req := httptest.NewRequest("POST", "/users/otp/login?realm=test", bytes.NewReader(body))
		req = addChiParams(req, map[string]string{"realm": "test"})
		w := httptest.NewRecorder()
		c.otpLoginHandler(w, req)
		if w.Code != 400 {
			t.Errorf("expected status 400, got %d", w.Code)
		}
	})

	t.Run("AccessDenied", func(t *testing.T) {
		mock.otpLoginFunc = func(realm string, login OTPLogin, gotConfig *app.Config) (*auth.TokenPair, error) {
			if login.ClientID != "client1" || login.Name != "user1" || gotConfig != config {
				t.Errorf("expected identity from challenge token, got %+v", login)
			}
			return nil, errOTPDenied
		}
		login := OTPLogin{ChallengeToken: challengeToken, OTP: "123456"}
		body, _ := json.Marshal(login)
		req := httptest.NewRequest("POST", "/users/otp/login?realm=test", bytes.NewReader(body))
		req = addChiParams(req, map[string]string{"realm": "test"})
		w := httptest.NewRecorder()
		c.otpLoginHandler(w, req)
		if w.Code != 401 {
			t.Errorf("expected status 401, got %d", w.Code)
		}
	})

	t.Run("InvalidChallenge", func(t *testing.T) {
		login := OTPLogin{ChallengeToken: "not-a-jwt", OTP: "123456"}
		body, _ := json.Marshal(login)
		req := httptest.NewRequest("POST", "/users/otp/login?realm=test", bytes.NewReader(body))
		w := httptest.NewRecorder()
		c.otpLoginHandler(w, req)
		if w.Code != 401 {
			t.Errorf("expected status 401, got %d", w.Code)
		}
	})

	t.Run("RepoError", func(t *testing.T) {
		mock.otpLoginFunc = func(realm string, login OTPLogin, gotConfig *app.Config) (*auth.TokenPair, error) {
			return nil, errors.New("repo error")
		}
		login := OTPLogin{ChallengeToken: challengeToken, OTP: "123456"}
		body, _ := json.Marshal(login)
		req := httptest.NewRequest("POST", "/users/otp/login?realm=test", bytes.NewReader(body))
		req = addChiParams(req, map[string]string{"realm": "test"})
		w := httptest.NewRecorder()
		c.otpLoginHandler(w, req)
		if w.Code != 500 {
			t.Errorf("expected status 500, got %d", w.Code)
		}
	})

	t.Run("Success", func(t *testing.T) {
		mock.otpLoginFunc = func(realm string, login OTPLogin, gotConfig *app.Config) (*auth.TokenPair, error) {
			if realm != "test" || login.ClientID != "client1" || login.Name != "user1" || login.ChallengeToken != challengeToken || login.OTP != "123456" {
				t.Errorf("unexpected OTP login request: %+v", login)
			}
			return &auth.TokenPair{AccessToken: "access", RefreshToken: "refresh"}, nil
		}
		login := OTPLogin{ChallengeToken: challengeToken, OTP: "123456"}
		body, _ := json.Marshal(login)
		req := httptest.NewRequest("POST", "/users/otp/login?realm=test", bytes.NewReader(body))
		req = addChiParams(req, map[string]string{"realm": "test"})
		w := httptest.NewRecorder()
		c.otpLoginHandler(w, req)
		if w.Code != 200 {
			t.Errorf("expected status 200, got %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), `"refreshToken":"refresh"`) {
			t.Errorf("expected full token pair after OTP verification, got %s", w.Body.String())
		}
	})
}
