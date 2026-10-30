// auth package implements JWT authentication and OTP handlers
package auth

// authentication, token generation and password encryption functions

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"junglerider/gatekeeper/app"

	"github.com/emersion/go-bcrypt"
	"github.com/gofrs/uuid/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
)

// represents either a user or a client entity
type Account interface {
	GetRealm() string
	GetClientID() string
	GetName() string
	GetAccess() *any
}

type AuthService interface {
	CreateTokenPair(acc Account, overrideClaims map[string]any, cfg app.Config) (*TokenPair, string, error)
	VerifyToken(tokenString string, publicKey string, expectedClaims map[string]any) (jwt.MapClaims, error)
	HashPassword(password *string) *string
	HashAPIKey(apiKey *string, realm string) *string
	VerifyPassword(hash, password *string) bool
}

// service implementation
type Service struct {
	Config *app.Config
}

// func NewService(config *app.Config) AuthService {
// 	 return &Service{config}
// }

// represents a pair of JSON Web Tokens
type TokenPair struct {
	AccessToken          string `json:"accessToken"`
	AccessTokenLifetime  int    `json:"expiresIn,omitempty"`
	RefreshToken         string `json:"refreshToken,omitempty"`
	RefreshTokenLifetime int    `json:"refreshExpiresIn,omitempty"`
}

// represents an authentication credential
type Credentials struct {
	AccessToken  string `json:"token"`
	RefreshToken string `json:"refreshToken"`
	ApiKey       string `json:"apiKey"`
}

// GenerateEd25519KeyPair returns a base64-encoded private seed and matching public key.
func GenerateEd25519KeyPair() (string, string, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate Ed25519 key pair: %w", err)
	}
	return base64.StdEncoding.EncodeToString(privateKey.Seed()),
		base64.StdEncoding.EncodeToString(publicKey), nil
}

// creates a single signed JWT token from claims and an Ed25519 private-key seed
func createToken(claims jwt.Claims, privateKeySeed string, tokenType string) (string, error) {
	decodedKey, err := base64.StdEncoding.DecodeString(privateKeySeed)
	if err != nil {
		return "", fmt.Errorf("decode JWT signing key: %w", err)
	}
	if len(decodedKey) != ed25519.SeedSize {
		return "", fmt.Errorf("JWT signing key must encode a %d-byte Ed25519 seed", ed25519.SeedSize)
	}
	// Create a new JWT token with claims
	privateKey := ed25519.NewKeyFromSeed(decodedKey)
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	if tokenType != "" {
		token.Header["typ"] = tokenType
	}

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

// constructs claims for a new JWT token
func createClaims(acc Account, tokenType string, realmConfig app.RealmConfig, lifetimes []int, overrideClaims map[string]any) jwt.Claims {
	log.Debug().Str("account", acc.GetName()).Str("realm", acc.GetRealm()).Msg("creating new token")
	subject := acc.GetName()
	if subject == "" {
		subject = acc.GetRealm()
	}
	tokenID, _ := uuid.NewV4()
	issuedAt := time.Now().Unix()
	claims := jwt.MapClaims{}
	// add default claims from application config
	for k, v := range realmConfig.Claims {
		claims[k] = v
	}
	lifetime := lifetimes[0]
	if tokenType != "at+jwt" {
		lifetime = lifetimes[1]
	}
	claims["iat"] = issuedAt                   // issued at
	claims["exp"] = issuedAt + int64(lifetime) // token expiration
	claims["jti"] = tokenID.String()           // token id
	claims["client_id"] = acc.GetClientID()    // client identifier
	claims["sub"] = subject                    // subject

	if tokenType == "at+jwt" && acc.GetAccess() != nil {
		claims["access"] = *acc.GetAccess()
	}
	for k, v := range overrideClaims {
		claims[k] = v
	}
	delete(claims, "typ")
	log.Trace().Interface("claims %v", claims).Msg("resulting token")
	return claims
}

// gets access token, refresh token and session lifetimes as array
func calcLifetimes(acc Account, realmConfig app.RealmConfig) []int {
	accessTokenLifetime := realmConfig.AccessTokenLifetime
	refreshTokenLifetime := realmConfig.RefreshTokenLifetime
	sessionLifetime := realmConfig.SessionMaxLifetime
	if acc.GetAccess() != nil {
		// token lifetimes can be overridden by account access settings
		jsonData := *acc.GetAccess()
		if access, ok := jsonData.(map[string]any); ok {
			if val, ok := access["_tok_ttl"].(map[string]any); ok {
				if val, ok := val["accessTokenLifetime"].(int); ok {
					accessTokenLifetime = val
				}
				if val, ok := val["refreshTokenLifetime"].(int); ok {
					refreshTokenLifetime = val
				}
				if val, ok := val["sessionMaxLifetime"].(int); ok {
					sessionLifetime = val
				}
			}
		}
	}
	return []int{accessTokenLifetime, refreshTokenLifetime, sessionLifetime}
}

// create a pair of new access and refresh tokens
func CreateTokenPair(acc Account, overrideClaims map[string]any, cfg app.Config) (*TokenPair, string, error) {
	realm := acc.GetRealm()
	realmConfig := cfg.Realms[realm]
	lifetimes := calcLifetimes(acc, realmConfig)
	if _, ok := overrideClaims["sid"]; !ok {
		sessionID, _ := uuid.NewV4()
		overrideClaims["sid"] = sessionID.String() // new session id
	}
	if _, ok := overrideClaims["sex"]; !ok {
		overrideClaims["sex"] = time.Now().Unix() + int64(lifetimes[2]) // new session expiration
	}
	accessClaims := createClaims(acc, "at+jwt", realmConfig, lifetimes, overrideClaims)
	refreshClaims := createClaims(acc, "rt+jwt", realmConfig, lifetimes, overrideClaims)
	var refreshToken string

	accessToken, err := createToken(accessClaims, realmConfig.SigningPrivateKey, "at+jwt")
	if err == nil {
		refreshToken, err = createToken(refreshClaims, realmConfig.SigningPrivateKey, "rt+jwt")
	}
	if err != nil {
		return nil, "", err
	}
	var tp = TokenPair{
		AccessToken:          accessToken,
		RefreshToken:         refreshToken,
		AccessTokenLifetime:  lifetimes[0],
		RefreshTokenLifetime: lifetimes[1],
	}
	refreshJTI := ""
	if claims, ok := refreshClaims.(jwt.MapClaims); ok {
		if jti, exists := claims["jti"].(string); exists {
			refreshJTI = jti
		} else {
			return &tp, "", fmt.Errorf("jti claim not found in refresh token")
		}
	}
	return &tp, refreshJTI, nil
}

// CreateChallengeToken creates a short-lived token proving password authentication.
func CreateChallengeToken(acc Account, cfg app.Config) (string, error) {
	log.Debug().Str("account", acc.GetName()).Str("realm", acc.GetRealm()).Msg("creating challenge token")
	realmConfig := cfg.Realms[acc.GetRealm()]
	issuedAt := time.Now().Unix()
	tokenID, err := uuid.NewV4()
	if err != nil {
		return "", fmt.Errorf("generate challenge token id: %w", err)
	}
	claims := jwt.MapClaims{
		"iat":       issuedAt,
		"exp":       issuedAt + int64((5 * time.Minute).Seconds()),
		"jti":       tokenID.String(),
		"client_id": acc.GetClientID(),
		"sub":       acc.GetName(),
		"realm":     acc.GetRealm(),
	}
	return createToken(claims, realmConfig.SigningPrivateKey, "challenge+jwt")
}

// VerifyChallengeToken verifies the type, realm, subject, and expiry of a challenge token.
func VerifyChallengeToken(tokenString string, publicKey string, realm string) (jwt.MapClaims, error) {
	token, err := parseToken(tokenString, publicKey)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("unable to parse JWT claims")
	}
	if headerType, ok := token.Header["typ"].(string); !ok || headerType != "challenge+jwt" {
		return nil, errors.New("invalid challenge token type")
	}
	if claims["realm"] != realm {
		return nil, errors.New("invalid challenge token realm")
	}
	issuedAt, issuedAtOK := claims["iat"].(float64)
	expiry, expiryOK := claims["exp"].(float64)
	if !issuedAtOK || !expiryOK || int64(expiry)-int64(issuedAt) != int64((5*time.Minute).Seconds()) {
		return nil, errors.New("challenge token expiry is missing or invalid")
	}
	if int64(issuedAt) > time.Now().Unix() {
		return nil, errors.New("challenge token issued in the future")
	}
	if clientID, ok := claims["client_id"].(string); !ok || clientID == "" {
		return nil, errors.New("challenge token client_id is missing or invalid")
	}
	if subject, ok := claims["sub"].(string); !ok || subject == "" {
		return nil, errors.New("challenge token subject is missing or invalid")
	}
	return claims, nil
}

// parse and verify the given token string
func VerifyToken(tokenString string, publicKey string, expectedClaims map[string]any) (jwt.MapClaims, error) {
	token, err := parseToken(tokenString, publicKey)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("unable to parse JWT claims")
	}
	if _, ok := claims["iat"]; !ok {
		return nil, errors.New("iat claim is required")
	}
	if _, ok := claims["exp"]; !ok {
		return nil, errors.New("exp claim is required")
	}
	if issuedAt, ok := claims["iat"].(float64); !ok || int64(issuedAt) > time.Now().Unix()+1 {
		return nil, errors.New("issued at claim is missing or invalid")
	}
	if sessionExpiry, ok := claims["sex"].(float64); !ok {
		return nil, fmt.Errorf("session claim invalid")
	} else if int64(sessionExpiry) < time.Now().Unix() {
		return nil, fmt.Errorf("session expired")
	}
	if expectedType, expected := expectedClaims["typ"]; expected {
		if typ, ok := token.Header["typ"].(string); !ok || fmt.Sprint(expectedType) != typ {
			return nil, fmt.Errorf("expected claim '%s' to be '%v', got '%v'", "typ", expectedType, typ)
		}
	}
	for key, expected := range expectedClaims {
		if key == "typ" {
			continue
		}
		if claim, ok := claims[key]; !ok || claim != expected {
			return nil, fmt.Errorf("expected claim '%s' to be '%v', got '%v'", key, expected, claim)
		}
	}
	return claims, nil
}

// UnverifiedTokenIdentity extracts token identity claims for logging rejected requests only.
func UnverifiedTokenIdentity(tokenString string) (clientID, userName string) {
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return "", ""
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", ""
	}
	clientID, _ = claims["client_id"].(string)
	userName, _ = claims["sub"].(string)
	return clientID, userName
}

// IsVerificationKeyError reports errors caused by invalid server-side JWT key configuration.
func IsVerificationKeyError(err error) bool {
	return err != nil && (strings.HasPrefix(err.Error(), "decode JWT verification key") ||
		strings.HasPrefix(err.Error(), "JWT verification key must encode"))
}

func parseToken(tokenString string, publicKey string) (*jwt.Token, error) {
	decodedKey, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return nil, fmt.Errorf("decode JWT verification key: %w", err)
	}
	if len(decodedKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("JWT verification key must encode a %d-byte Ed25519 public key", ed25519.PublicKeySize)
	}
	return jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodEdDSA {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return ed25519.PublicKey(decodedKey), nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}))
}

/* password encryption functions *******************************************************/

// encrypts a non-nil password with bcrypt algorithm
func HashPassword(password *string) *string {
	if password == nil {
		return nil
	}
	bytes, _ := bcrypt.GenerateFromPassword([]byte(*password), 10)
	hash := string(bytes)
	return &hash
}

// encrypts a non-nil API key with bcrypt algorithm
func HashAPIKey(apiKey *string, realm string) *string {
	if apiKey == nil {
		return nil
	}
	combined := *apiKey + realm
	bytes := sha256.Sum256([]byte(combined))
	hash := hex.EncodeToString(bytes[:])

	return &hash
}

// checks password with bcrypt algorithm
func VerifyPassword(hash, password *string) bool {
	if password == nil || hash == nil {
		return false
	}
	err := bcrypt.CompareHashAndPassword([]byte(*hash), []byte(*password))
	return err == nil
}

/* access verification ****************************************************************/

// returns a function verifying access tokens of the internal realm, which guards the CRUD
// endpoints. It returns the token claims if the token is a valid access token.
func VerifyAccess(config *app.Config) func(token string) (map[string]any, error) {
	return func(token string) (map[string]any, error) {
		realmConfig, ok := config.Realms[app.BootstrapRealm]
		if !ok {
			return nil, fmt.Errorf("realm %q is not configured", app.BootstrapRealm)
		}
		expectedClaims := map[string]any{"typ": "at+jwt"}
		for _, name := range []string{"iss", "aud"} {
			if value, ok := realmConfig.Claims[name]; ok {
				expectedClaims[name] = value
			}
		}
		return VerifyToken(token, realmConfig.VerificationPublicKey, expectedClaims)
	}
}
