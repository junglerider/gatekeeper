package client

import (
	"net/http"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
)

func TestGetClientID(t *testing.T) {
	client := &Client{ClientID: "client123"}
	assert.Equal(t, "client123", client.GetClientID(), "GetClientID should return the client ID")
}

func TestGetRealm(t *testing.T) {
	client := &Client{Realm: "test-realm"}
	assert.Equal(t, "test-realm", client.GetRealm(), "GetRealm should return the realm")
}

func TestGetName(t *testing.T) {
	client := &Client{}
	assert.Equal(t, "", client.GetName(), "GetName should return empty string")
}

func TestGetAccess(t *testing.T) {
	var access any = map[string]string{"foo": "bar"}
	client := &Client{AccessData: &access}
	assert.Equal(t, &access, client.GetAccess())
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
		"GET /clients",
		"GET /clients/{clientId}",
		"POST /clients",
		"PATCH /clients/{clientId}",
		"DELETE /clients/{clientId}",
		"POST /clients/login",
		"POST /clients/auth",
		"POST /clients/refresh",
		"POST /clients/logout",
	}
	assert.Subset(t, routes, expected)
}
