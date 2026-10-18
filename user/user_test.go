package user

import (
	"net/http"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
)

func TestGetClientID(t *testing.T) {
	user := &User{ClientID: "client123"}
	assert.Equal(t, "client123", user.GetClientID(), "GetClientID should return the client ID")
}

func TestGetRealm(t *testing.T) {
	user := &User{Realm: "test-realm"}
	assert.Equal(t, "test-realm", user.GetRealm(), "GetRealm should return the realm")
}

func TestGetName(t *testing.T) {
	user := &User{}
	assert.Equal(t, "", user.GetName(), "GetName should return empty string")
}

func TestGetAccess(t *testing.T) {
	var access any = map[string]string{"foo": "bar"}
	user := &User{AccessData: &access}
	assert.Equal(t, &access, user.GetAccess())
}

func TestRegisterRoutes(t *testing.T) {
	ctrl := &Controller{}
	r := chi.NewRouter()
	ctrl.RegisterRoutes(r, r)

	routes := []string{}
	walkFunc := func(method string, route string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		routes = append(routes, method+" "+route)
		return nil
	}
	err := chi.Walk(r, walkFunc)
	assert.NoError(t, err)

	expected := []string{
		"GET /users",
		"GET /users/{clientId}/{name}",
		"POST /users",
		"PATCH /users/{clientId}/{name}",
		"DELETE /users/{clientId}/{name}",
		"POST /users/login",
		"POST /users/otp/login",
		"POST /users/auth",
		"POST /users/refresh",
		"POST /users/logout",
	}
	assert.Subset(t, routes, expected)
}
