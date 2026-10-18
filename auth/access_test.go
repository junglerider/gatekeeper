package auth

import (
	"testing"

	"junglerider/gatekeeper/app"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func accessTestConfig() *app.Config {
	internalPrivateKey, internalPublicKey := encodedTestKeyPair(8)
	apiPrivateKey, apiPublicKey := encodedTestKeyPair(9)
	return &app.Config{Realms: map[string]app.RealmConfig{
		"internal": {
			SigningPrivateKey:     internalPrivateKey,
			VerificationPublicKey: internalPublicKey,
			AccessTokenLifetime:   300,
			RefreshTokenLifetime:  600,
			SessionMaxLifetime:    3600,
			Claims:                map[string]any{"iss": "internal-issuer", "aud": "admins"},
		},
		"api": {
			SigningPrivateKey:     apiPrivateKey,
			VerificationPublicKey: apiPublicKey,
			AccessTokenLifetime:   300,
			RefreshTokenLifetime:  600,
			SessionMaxLifetime:    3600,
		},
	}}
}

func tokenPair(t *testing.T, cfg *app.Config, realm string, access any) *TokenPair {
	t.Helper()
	acc := mockAccount{realm: realm, clientID: "internal", name: "admin"}
	if access != nil {
		acc.access = &access
	}
	pair, _, err := CreateTokenPair(acc, map[string]any{}, *cfg)
	require.NoError(t, err)
	return pair
}

func TestVerifyAccess(t *testing.T) {
	cfg := accessTestConfig()
	access := map[string]any{"gatekeeper": []any{"admin"}}
	verify := VerifyAccess(cfg)

	claims, err := verify(tokenPair(t, cfg, "internal", access).AccessToken)
	require.NoError(t, err)
	assert.Equal(t, access, claims["access"])
}

func TestVerifyAccess_Rejected(t *testing.T) {
	cfg := accessTestConfig()
	access := map[string]any{"gatekeeper": []any{"admin"}}
	verify := VerifyAccess(cfg)

	_, err := verify(tokenPair(t, cfg, "api", access).AccessToken)
	assert.Error(t, err, "token of another realm")

	_, err = verify(tokenPair(t, cfg, "internal", access).RefreshToken)
	assert.Error(t, err, "refresh token")

	_, err = verify("garbage")
	assert.Error(t, err, "malformed token")

	token := tokenPair(t, cfg, "internal", access).AccessToken
	cfg.Realms["internal"].Claims["iss"] = "someone-else"
	_, err = verify(token)
	assert.Error(t, err, "wrong issuer")
}

func TestVerifyAccess_InternalRealmMissing(t *testing.T) {
	_, err := VerifyAccess(&app.Config{Realms: map[string]app.RealmConfig{}})("abc")
	assert.ErrorContains(t, err, "not configured")
}
