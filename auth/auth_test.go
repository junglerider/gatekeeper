package auth

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"

	"junglerider/gatekeeper/app"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func encodedTestKeyPair(seedByte byte) (string, string) {
	seed := bytes.Repeat([]byte{seedByte}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	return base64.StdEncoding.EncodeToString(seed),
		base64.StdEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey))
}

func TestGenerateEd25519KeyPair(t *testing.T) {
	signingPrivateKey, verificationPublicKey, err := GenerateEd25519KeyPair()
	require.NoError(t, err)
	seed, err := base64.StdEncoding.DecodeString(signingPrivateKey)
	require.NoError(t, err)
	publicKey, err := base64.StdEncoding.DecodeString(verificationPublicKey)
	require.NoError(t, err)
	require.Len(t, seed, ed25519.SeedSize)
	require.Len(t, publicKey, ed25519.PublicKeySize)
	assert.Equal(t, ed25519.NewKeyFromSeed(seed).Public(), ed25519.PublicKey(publicKey))
}

// Mock implementation of Account interface for testing
type mockAccount struct {
	realm    string
	clientID string
	name     string
	access   *any
}

func (m mockAccount) GetRealm() string    { return m.realm }
func (m mockAccount) GetClientID() string { return m.clientID }
func (m mockAccount) GetName() string     { return m.name }
func (m mockAccount) GetAccess() *any     { return m.access }

func TestCreateTokenPair(t *testing.T) {
	privateKey, publicKey := encodedTestKeyPair(1)
	// Setup test config
	cfg := app.Config{
		Realms: map[string]app.RealmConfig{
			"test": {
				SigningPrivateKey:     privateKey,
				VerificationPublicKey: publicKey,
				AccessTokenLifetime:   300,
				RefreshTokenLifetime:  3600,
				SessionMaxLifetime:    43200,
				Claims: map[string]interface{}{
					"iss": "test-issuer",
				},
			},
		},
	}

	tests := []struct {
		name           string
		account        Account
		overrideClaims map[string]any
		wantErr        bool
	}{
		{
			name: "Valid token pair creation",
			account: mockAccount{
				realm:    "test",
				clientID: "client123",
				name:     "testuser",
			},
			overrideClaims: map[string]any{},
			wantErr:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenPair, refreshJTI, err := CreateTokenPair(tt.account, tt.overrideClaims, cfg)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.NotEmpty(t, tokenPair.AccessToken)
			assert.NotEmpty(t, tokenPair.RefreshToken)
			assert.NotEmpty(t, refreshJTI)
			assert.Equal(t, 300, tokenPair.AccessTokenLifetime)
			assert.Equal(t, 3600, tokenPair.RefreshTokenLifetime)
			publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKey)
			require.NoError(t, err)
			parsedToken, err := jwt.Parse(tokenPair.AccessToken, func(token *jwt.Token) (any, error) {
				return ed25519.PublicKey(publicKeyBytes), nil
			})
			require.NoError(t, err)
			require.True(t, parsedToken.Valid)
			assert.Equal(t, jwt.SigningMethodEdDSA.Alg(), parsedToken.Header["alg"])
			assert.Equal(t, "at+jwt", parsedToken.Header["typ"])

			// Verify the access token
			claims, err := VerifyToken(tokenPair.AccessToken, cfg.Realms["test"].VerificationPublicKey, map[string]any{
				"typ": "at+jwt",
				"iss": "test-issuer",
			})
			assert.NoError(t, err)
			assert.NotContains(t, claims, "typ")
			assert.Equal(t, "client123", claims["client_id"])
			assert.Equal(t, "testuser", claims["sub"])
		})
	}
}

func TestCreateTokenPairRejectsUnserializableClaims(t *testing.T) {
	privateKey, publicKey := encodedTestKeyPair(2)
	cfg := app.Config{Realms: map[string]app.RealmConfig{
		"test": {SigningPrivateKey: privateKey, VerificationPublicKey: publicKey},
	}}
	_, _, err := CreateTokenPair(mockAccount{realm: "test"}, map[string]any{"invalid": make(chan int)}, cfg)
	require.Error(t, err)
}

func TestChallengeToken(t *testing.T) {
	privateKey, publicKey := encodedTestKeyPair(3)
	cfg := app.Config{Realms: map[string]app.RealmConfig{
		"test": {SigningPrivateKey: privateKey, VerificationPublicKey: publicKey},
	}}
	account := mockAccount{realm: "test", clientID: "client123", name: "testuser"}
	tokenString, err := CreateChallengeToken(account, cfg)
	require.NoError(t, err)
	require.NotEmpty(t, tokenString)

	claims, err := VerifyChallengeToken(tokenString, cfg.Realms["test"].VerificationPublicKey, "test")
	require.NoError(t, err)
	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKey)
	require.NoError(t, err)
	parsed, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		return ed25519.PublicKey(publicKeyBytes), nil
	})
	require.NoError(t, err)
	assert.Equal(t, "challenge+jwt", parsed.Header["typ"])
	assert.NotContains(t, claims, "typ")
	assert.Equal(t, "client123", claims["client_id"])
	assert.Equal(t, "testuser", claims["sub"])
	assert.Equal(t, "test", claims["realm"])
	assert.Equal(t, int64(300), int64(claims["exp"].(float64))-int64(claims["iat"].(float64)))
	assert.NotEmpty(t, claims["jti"])

	_, err = VerifyChallengeToken(tokenString, cfg.Realms["test"].VerificationPublicKey, "another-realm")
	require.Error(t, err)
}

func TestVerifyChallengeTokenRejectsAccessTokens(t *testing.T) {
	privateKey, publicKey := encodedTestKeyPair(4)
	cfg := app.Config{Realms: map[string]app.RealmConfig{"test": {
		SigningPrivateKey: privateKey, VerificationPublicKey: publicKey,
		AccessTokenLifetime: 300, RefreshTokenLifetime: 3600, SessionMaxLifetime: 7200,
	}}}
	tokenPair, _, err := CreateTokenPair(mockAccount{realm: "test", clientID: "client123", name: "testuser"}, map[string]any{}, cfg)
	require.NoError(t, err)
	_, err = VerifyChallengeToken(tokenPair.AccessToken, publicKey, "test")
	require.Error(t, err)
}

func TestVerifyChallengeTokenRejectsExpiredTokens(t *testing.T) {
	privateKey, publicKey := encodedTestKeyPair(5)
	issuedAt := time.Now().Add(-6 * time.Minute).Unix()
	claims := jwt.MapClaims{
		"iat":       issuedAt,
		"exp":       issuedAt + int64((5 * time.Minute).Seconds()),
		"client_id": "client123",
		"sub":       "testuser",
		"realm":     "test",
	}
	tokenString, err := createToken(claims, privateKey, "challenge+jwt")
	require.NoError(t, err)
	_, err = VerifyChallengeToken(tokenString, publicKey, "test")
	require.Error(t, err)
}

func TestCreateClaims(t *testing.T) {
	access := any([]string{"read"})
	claims := createClaims(mockAccount{
		realm: "client", clientID: "client-1", access: &access,
	}, "at+jwt", app.RealmConfig{Claims: map[string]any{"iss": "issuer"}}, []int{300, 3600}, map[string]any{"role": "admin"}).(jwt.MapClaims)
	assert.Equal(t, "client", claims["sub"])
	assert.Equal(t, "client-1", claims["client_id"])
	assert.NotContains(t, claims, "config")
	assert.Equal(t, []string{"read"}, claims["access"])
	assert.Equal(t, "issuer", claims["iss"])
	assert.Equal(t, "admin", claims["role"])
	assert.NotEmpty(t, claims["jti"])
	assert.NotContains(t, claims, "typ")

	apiClaims := createClaims(mockAccount{realm: "api", name: "named"}, "at+jwt", app.RealmConfig{}, []int{300, 3600}, nil).(jwt.MapClaims)
	assert.Equal(t, "named", apiClaims["sub"])
	assert.NotContains(t, apiClaims, "access")

	refreshClaims := createClaims(mockAccount{realm: "client", access: &access}, "rt+jwt", app.RealmConfig{}, []int{300, 3600}, nil).(jwt.MapClaims)
	assert.Equal(t, int64(refreshClaims["iat"].(int64))+3600, refreshClaims["exp"])
	assert.NotContains(t, refreshClaims, "config")
	assert.NotContains(t, refreshClaims, "access")
	assert.NotContains(t, refreshClaims, "typ")
}

func TestCalcLifetimes(t *testing.T) {
	tests := []struct {
		name    string
		account mockAccount
		config  app.RealmConfig
		want    []int
	}{
		{
			name:    "configured non-api lifetimes",
			account: mockAccount{realm: "client"},
			config:  app.RealmConfig{AccessTokenLifetime: 600, RefreshTokenLifetime: 7200, SessionMaxLifetime: 9000},
			want:    []int{600, 7200, 9000},
		},
		{
			name: "account access settings override configured lifetimes",
			account: mockAccount{realm: "client", access: func() *any {
				value := any(map[string]any{"_tok_ttl": map[string]any{"accessTokenLifetime": 500, "refreshTokenLifetime": 4000, "sessionMaxLifetime": 8000}})
				return &value
			}()},
			config: app.RealmConfig{AccessTokenLifetime: 1, RefreshTokenLifetime: 1, SessionMaxLifetime: 1},
			want:   []int{500, 4000, 8000},
		},
		{
			name: "wrongly typed access settings leave configured lifetimes unchanged",
			account: mockAccount{realm: "api", access: func() *any {
				value := any(map[string]any{"_tok_ttl": map[string]any{"accessTokenLifetime": "500", "refreshTokenLifetime": 4000.0}})
				return &value
			}()},
			config: app.RealmConfig{AccessTokenLifetime: 600, RefreshTokenLifetime: 7200, SessionMaxLifetime: 9000},
			want:   []int{600, 7200, 9000},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, calcLifetimes(tt.account, tt.config))
		})
	}
}

func TestVerifyToken(t *testing.T) {
	privateKey, publicKey := encodedTestKeyPair(6)
	acc := mockAccount{
		realm:    "test",
		clientID: "client123",
		name:     "testuser",
	}

	// Create a valid token for testing
	claims := createClaims(acc, "at+jwt", app.RealmConfig{
		SigningPrivateKey: privateKey,
		Claims: map[string]interface{}{
			"iss": "test-issuer",
		},
	}, []int{300, 3600}, map[string]any{
		"sex": time.Now().Unix() + 3600, // Set session expiry 1 hour in the future
	})

	token, err := createToken(claims, privateKey, "at+jwt")
	assert.NoError(t, err)

	tests := []struct {
		name           string
		token          string
		publicKey      string
		expectedClaims map[string]any
		wantErr        bool
	}{
		{
			name:      "Valid token verification",
			token:     token,
			publicKey: publicKey,
			expectedClaims: map[string]any{
				"typ": "at+jwt",
			},
			wantErr: false,
		},
		{
			name:      "Invalid key",
			token:     token,
			publicKey: "wrong-key",
			expectedClaims: map[string]any{
				"typ": "at+jwt",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, err := VerifyToken(tt.token, tt.publicKey, tt.expectedClaims)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.NotContains(t, claims, "typ")
			assert.Equal(t, "client123", claims["client_id"])
			assert.Equal(t, "testuser", claims["sub"])
		})
	}
}

func TestVerifyTokenRejectsInvalidClaimsAndMethods(t *testing.T) {
	privateKey, publicKey := encodedTestKeyPair(7)
	now := time.Now().Unix()
	tests := []struct {
		name   string
		claims jwt.MapClaims
	}{
		{name: "missing session expiry", claims: jwt.MapClaims{"exp": now + 3600}},
		{name: "invalid session expiry type", claims: jwt.MapClaims{"sex": "later", "exp": now + 3600}},
		{name: "expired session", claims: jwt.MapClaims{"sex": now - 1, "exp": now + 3600}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := createToken(tt.claims, privateKey, "")
			require.NoError(t, err)
			_, err = VerifyToken(token, publicKey, nil)
			require.Error(t, err)
		})
	}

	validClaims := jwt.MapClaims{"sex": now + 3600, "exp": now + 3600, "iat": now, "role": "user"}
	validToken, err := createToken(validClaims, privateKey, "")
	require.NoError(t, err)
	_, err = VerifyToken(validToken, publicKey, map[string]any{"role": "admin"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected claim 'role'")

	noneToken, err := jwt.NewWithClaims(jwt.SigningMethodNone, validClaims).SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)
	_, err = VerifyToken(noneToken, publicKey, nil)
	require.Error(t, err)

	legacyToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, validClaims).SignedString([]byte("legacy-secret"))
	require.NoError(t, err)
	_, err = VerifyToken(legacyToken, publicKey, nil)
	require.Error(t, err)
}

func TestPasswordHashing(t *testing.T) {
	tests := []struct {
		name     string
		password string
	}{
		{
			name:     "Valid password hashing and verification",
			password: "test-password",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test password hashing
			hash := HashPassword(&tt.password)
			assert.NotNil(t, hash)
			assert.NotEqual(t, tt.password, *hash)

			// Test password verification
			assert.True(t, VerifyPassword(hash, &tt.password))

			// Test wrong password
			wrongPass := "wrong-password"
			assert.False(t, VerifyPassword(hash, &wrongPass))
		})
	}
}

func TestPasswordAndAPIKeyNilInputs(t *testing.T) {
	assert.Nil(t, HashPassword(nil))
	assert.Nil(t, HashAPIKey(nil, "realm"))
	assert.False(t, VerifyPassword(nil, nil))
	password := "password"
	assert.False(t, VerifyPassword(nil, &password))
	assert.False(t, VerifyPassword(&password, nil))
	invalidHash := "not-a-bcrypt-hash"
	assert.False(t, VerifyPassword(&invalidHash, &password))
}

func TestAPIKeyHashing(t *testing.T) {
	tests := []struct {
		name   string
		apiKey string
		salt   string
	}{
		{
			name:   "Valid API key hashing",
			apiKey: "test-api-key",
			salt:   "test-salt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test API key hashing
			hash := HashAPIKey(&tt.apiKey, tt.salt)
			assert.NotNil(t, hash)
			assert.NotEqual(t, tt.apiKey, *hash)
		})
	}
}
