package client

// controller implementation for client accounts

import (
	"database/sql"
	"encoding/json"
	"errors"
	"junglerider/gatekeeper/app"
	"junglerider/gatekeeper/auth"
	"junglerider/gatekeeper/utils"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type Controller struct {
	*app.BaseController
	repo ClientRepo
}

func NewController(repo ClientRepo, config *app.Config) *Controller {
	return &Controller{
		&app.BaseController{Config: config},
		repo,
	}
}

func tokenAuthFailureEvent(err error) *zerolog.Event {
	if auth.IsVerificationKeyError(err) {
		return log.Error().Err(err)
	}
	return log.Info().Err(err)
}

// registers all client routes
func (c *Controller) RegisterRoutes(public chi.Router, protected chi.Router) {
	protected.Get("/clients", c.listHandler)
	protected.Get("/clients/{clientId}", c.readHandler)
	protected.Post("/clients", c.createHandler)
	protected.Patch("/clients/{clientId}", c.updateHandler)
	protected.Delete("/clients/{clientId}", c.deleteHandler)
	public.Post("/clients/login", c.loginHandler)
	public.Post("/clients/auth", c.authHandler)
	public.Post("/clients/refresh", c.refreshHandler)
	public.Post("/clients/logout", c.logoutHandler)
}

// retrieves a list of client ids
func (c *Controller) listHandler(w http.ResponseWriter, r *http.Request) {
	realm := c.DefaultRealm(r.URL.Query().Get("realm"))
	err := c.ValidateRealm(realm)
	if err != nil {
		c.StatusReply(w, 400, err.Error())
		return
	}
	var isActive *bool
	if isActiveParam, err := strconv.ParseBool(r.URL.Query().Get("isActive")); err == nil {
		isActive = &isActiveParam
	}
	var expiry *time.Time
	if expiryParam := r.URL.Query().Get("expiry"); expiryParam != "" {
		parsedExpiry, parseErr := time.Parse(time.RFC3339Nano, expiryParam)
		if parseErr != nil {
			c.StatusReply(w, 400, "expiry must be an RFC3339 timestamp")
			return
		}
		expiry = &parsedExpiry
	}
	var clients []string
	clients, err = c.repo.ListClients(realm, isActive, expiry)
	if err != nil {
		log.Error().Err(err).Msg("cannot retrieve list of client accounts:")
		c.StatusReply(w, 500)
		return
	}
	c.DataReply(w, 200, clients)
}

// retrieves a specific client account by realm and client id
func (c *Controller) readHandler(w http.ResponseWriter, r *http.Request) {
	clientID := chi.URLParam(r, "clientId")
	realm := c.DefaultRealm(r.URL.Query().Get("realm"))
	err := errors.Join(c.ValidateString(clientID, "client id", 0, 16, true), c.ValidateRealm(realm))
	if err != nil {
		c.StatusReply(w, 400, err.Error())
		return
	}
	var client *Client
	client, err = c.repo.ReadClient(realm, clientID)
	if err != nil {
		if err == sql.ErrNoRows {
			c.StatusReply(w, 404)
		} else {
			log.Error().Str("clientId", clientID).Err(err).Msg("cannot read client account:")
			c.StatusReply(w, 500)
		}
		return
	}
	if client.Password != nil {
		*client.Password = "*****"
	}
	if client.APIKey != nil {
		*client.APIKey = "*****"
	}
	c.DataReply(w, 200, client)
}

// creates a new client account
func (c *Controller) createHandler(w http.ResponseWriter, r *http.Request) {
	var client Client
	err := json.NewDecoder(r.Body).Decode(&client)
	if err == nil {
		client.Realm = c.DefaultRealm(client.Realm)
		minPasswordLength := c.MinPasswordLength(client.Realm)
		err = errors.Join(
			c.ValidateRealm(client.Realm),
			c.ValidateString(client.ClientID, "client id", 1, 16, true),
			c.ValidateStringPtr(client.APIKey, "api key", 10, 64, false),
			c.ValidateStringPtr(client.Password, "password", minPasswordLength, 64, client.Password != nil),
		)
	}
	if err == nil {
		if client.Password == nil && client.APIKey == nil {
			err = errors.New("either a password or apiKey must be provided")
		}
	}
	if err == nil && client.IsActive == nil {
		isActive := true
		client.IsActive = &isActive
	}
	if err != nil {
		c.StatusReply(w, 400, err.Error())
		return
	}
	err = c.repo.CreateClient(client, client.Realm)
	if err != nil {
		log.Error().Str("clientId", client.ClientID).Err(err).Msg("cannot create client account:")
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") {
			c.StatusReply(w, 409, err.Error())
		} else {
			c.StatusReply(w, 500)
		}
		return
	}
	var response = map[string]any{
		"message":  "created",
		"realm":    client.Realm,
		"clientId": client.ClientID,
	}
	c.DataReply(w, 201, response)
}

// updates a given client account
func (c *Controller) updateHandler(w http.ResponseWriter, r *http.Request) {
	clientID := chi.URLParam(r, "clientId")
	realm := c.DefaultRealm(r.URL.Query().Get("realm"))
	err := errors.Join(c.ValidateString(clientID, "client id", 0, 16, true), c.ValidateRealm(realm))
	var props map[string]any
	if err == nil {
		props, err = readUpdateProps(c, r, realm)
	}
	if err != nil {
		c.StatusReply(w, 400, err.Error())
		return
	}
	updatedRows, err := c.repo.UpdateClient(clientID, realm, props)
	if err != nil {
		log.Error().Str("clientId", clientID).Err(err).Msg("cannot update client account:")
		c.StatusReply(w, 500)
	} else if updatedRows == 0 {
		c.StatusReply(w, 404)
	} else {
		w.WriteHeader(204)
	}
}

// reads the client update properties from the request body
func readUpdateProps(c *Controller, r *http.Request, realm string) (map[string]any, error) {
	props := make(map[string]any, 3)
	input := make(map[string]any)
	err := json.NewDecoder(r.Body).Decode(&input)
	if err != nil {
		return props, err
	}
	log.Trace().Interface("input", input).Msg("received:")
	for k, v := range input {
		switch k {
		case "apiKey":
			if s, ok := v.(string); ok {
				err = c.ValidateString(s, "api key", 10, 64, false)
				realm := c.DefaultRealm(r.URL.Query().Get("realm"))
				props["api_key"] = auth.HashAPIKey(&s, realm)
			} else if v == nil {
				props["api_key"] = nil
			}
		case "password":
			if s, ok := v.(string); ok {
				err = c.ValidateString(s, "password", c.MinPasswordLength(realm), 64, true)
				props["password"] = auth.HashPassword(&s)
			} else if v == nil {
				props["password"] = nil
			}
		case "isActive":
			if b, ok := v.(bool); ok {
				props["is_active"] = b
			} else {
				err = errors.New("isActive must be of type boolean")
			}
		case "access":
			if v != nil {
				var data *string
				data, err = utils.JSONToStr(&v)
				if err == nil && data != nil {
					props[k] = *data
				}
			} else {
				props[k] = nil
			}
		case "pwdExpiry":
			if s, ok := v.(string); ok {
				var expiry time.Time
				expiry, err = time.Parse(time.RFC3339Nano, s)
				if err == nil {
					props["pwd_expiry"] = expiry
				}
			} else if v == nil {
				props["pwd_expiry"] = nil
			} else {
				err = errors.New("pwdExpiry must be a timestamp or null")
			}
		}
		if err != nil {
			break
		}
	}
	if err == nil && len(props) == 0 {
		err = errors.New("no updatable properties were found in the request body")
	}
	return props, err
}

// deletes a given client account
func (c *Controller) deleteHandler(w http.ResponseWriter, r *http.Request) {
	realm := r.URL.Query().Get("realm")
	clientID := chi.URLParam(r, "clientId")
	err := c.ValidateString(clientID, "client id", 1, 16, true)
	if err == nil && realm != "" {
		err = c.ValidateRealm(realm)
	}
	if err != nil {
		c.StatusReply(w, 400, err.Error())
		return
	}
	deletedRows, err := c.repo.DeleteClient(clientID, realm)
	if err != nil {
		log.Error().Str("clientId", clientID).Err(err).Msg("cannot delete client account:")
		c.StatusReply(w, 500)
	} else if deletedRows == 0 {
		c.StatusReply(w, 404)
	} else {
		w.WriteHeader(204)
	}
}

// JWT login with a client account
func (c *Controller) loginHandler(w http.ResponseWriter, r *http.Request) {
	var client Client
	var tokenPair *auth.TokenPair
	err := json.NewDecoder(r.Body).Decode(&client)
	client.Realm = c.DefaultRealm(r.URL.Query().Get("realm"))
	if err == nil {
		err = errors.Join(
			c.ValidateString(client.ClientID, "client id", 1, 16, true),
			c.ValidateStringPtr(client.Password, "password", 1, 64, true),
			c.ValidateRealm(client.Realm),
		)
	}
	if err != nil {
		log.Info().Err(err).
			Str("realm", client.Realm).
			Str("client_id", client.ClientID).
			Msg("login rejected")
		c.StatusReply(w, 400, err.Error())
		return
	}
	tokenPair, err = c.repo.LoginClient(&client, c.Config)
	if err != nil {
		if errors.Is(err, errPasswordExpired) {
			log.Info().Err(err).
				Str("realm", client.Realm).
				Str("client_id", client.ClientID).
				Msg("login rejected")
			c.StatusReply(w, 401, errPasswordExpired.Error())
		} else if errors.Is(err, errClientCredentialsDenied) {
			log.Info().Err(err).
				Str("realm", client.Realm).
				Str("client_id", client.ClientID).
				Msg("login rejected")
			c.StatusReply(w, 401, "credentials not recognised")
		} else {
			log.Error().Err(err).
				Str("realm", client.Realm).
				Str("client_id", client.ClientID).
				Msg("login failed")
			c.StatusReply(w, 500)
		}
		return
	}
	c.DataReply(w, 200, tokenPair)
}

// authenticates a JWT token or an API key
func (c *Controller) authHandler(w http.ResponseWriter, r *http.Request) {
	var creds auth.Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	realm := c.DefaultRealm(r.URL.Query().Get("realm"))
	if err == nil {
		err = c.ValidateRealm(realm)
	}
	if err != nil {
		c.StatusReply(w, 400, err.Error())
		return
	}
	claims := make(jwt.MapClaims)
	if creds.ApiKey != "" {
		if result, err := c.repo.VerifyAPIKey(creds.ApiKey, realm, c.Config); err != nil {
			event := log.Info().Err(err).Str("realm", realm).Str("client_id", "")
			if !errors.Is(err, errInvalidAPIKey) {
				event = log.Error().Err(err).Str("realm", realm).Str("client_id", "")
			}
			event.Msg("API key authentication failed")
			c.StatusReply(w, 401, "invalid or expired API key")
			return
		} else {
			for k, v := range result {
				claims[k] = v
			}
		}
	} else if creds.AccessToken == "" {
		log.Info().Str("realm", realm).Str("client_id", "").Msg("authentication credentials missing")
		c.StatusReply(w, 400, "token is required for authentication")
		return
	} else {
		realmConfig := c.Config.Realms[realm]
		expectedClaims := make(map[string]any, 3)
		expectedClaims["typ"] = "at+jwt"
		if value, ok := realmConfig.Claims["iss"]; ok {
			expectedClaims["iss"] = value
		}
		if value, ok := realmConfig.Claims["aud"]; ok {
			expectedClaims["aud"] = value
		}
		if claims, err = auth.VerifyToken(creds.AccessToken, realmConfig.VerificationPublicKey, expectedClaims); err != nil {
			clientID, _ := auth.UnverifiedTokenIdentity(creds.AccessToken)
			tokenAuthFailureEvent(err).
				Str("realm", realm).
				Str("client_id", clientID).
				Msg("access token authentication failed")
			c.StatusReply(w, 401, "invalid or expired access token")
			return
		}
	}
	c.DataReply(w, 200, claims)
}

// refreshes access token using refresh token
func (c *Controller) refreshHandler(w http.ResponseWriter, r *http.Request) {
	var tok auth.TokenPair
	err := json.NewDecoder(r.Body).Decode(&tok)
	realm := c.DefaultRealm(r.URL.Query().Get("realm"))
	if err == nil {
		err = c.ValidateRealm(realm)
	}
	if tok.RefreshToken == "" {
		err = errors.New("refresh token is required")
	}
	if err != nil {
		log.Info().Err(err).Str("realm", realm).Str("client_id", "").Msg("refresh token missing")
		c.StatusReply(w, 400, err.Error())
		return
	}
	realmConfig := c.Config.Realms[realm]
	expectedClaims := make(map[string]any, 3)
	expectedClaims["typ"] = "rt+jwt"
	if value, ok := realmConfig.Claims["iss"]; ok {
		expectedClaims["iss"] = value
	}
	if value, ok := realmConfig.Claims["aud"]; ok {
		expectedClaims["aud"] = value
	}
	var claims jwt.MapClaims
	if claims, err = auth.VerifyToken(tok.RefreshToken, realmConfig.VerificationPublicKey, expectedClaims); err != nil {
		clientID, _ := auth.UnverifiedTokenIdentity(tok.RefreshToken)
		tokenAuthFailureEvent(err).
			Str("realm", realm).
			Str("client_id", clientID).
			Msg("refresh token authentication failed")
		c.StatusReply(w, 401, "invalid refresh token")
		return
	}
	tokenPair, err := c.repo.RefreshToken(claims, realm, c.Config)
	if err != nil {
		clientID, _ := claims["client_id"].(string)
		authFailure := errors.Is(err, errPasswordExpired) || errors.Is(err, sql.ErrNoRows) ||
			errors.Is(err, errClientCredentialsDenied) || errors.Is(err, errClientRefreshTokenReuse) ||
			strings.Contains(err.Error(), "claim is not valid")
		if authFailure {
			log.Info().Err(err).
				Str("realm", realm).
				Str("client_id", clientID).
				Msg("refresh token authentication failed")
		} else {
			log.Error().Err(err).
				Str("realm", realm).
				Str("client_id", clientID).
				Msg("failed to refresh token")
		}
		switch {
		case errors.Is(err, errClientRefreshTokenReuse):
			c.StatusReply(w, 401, "refresh token cannot be reused")
		default:
			c.StatusReply(w, 500, "failed to refresh token")
		}
		return
	}
	c.DataReply(w, 200, tokenPair)
}

// logs out client account
func (c *Controller) logoutHandler(w http.ResponseWriter, r *http.Request) {
	var tok auth.TokenPair
	err := json.NewDecoder(r.Body).Decode(&tok)
	realm := c.DefaultRealm(r.URL.Query().Get("realm"))
	if err == nil {
		err = c.ValidateRealm(realm)
	}
	if tok.RefreshToken == "" {
		err = errors.New("refresh token is required")
	}
	if err != nil {
		log.Info().Err(err).Str("realm", realm).Str("client_id", "").Msg("logout token missing")
		c.StatusReply(w, 400, err.Error())
		return
	}
	realmConfig := c.Config.Realms[realm]
	expectedClaims := make(map[string]any, 3)
	expectedClaims["typ"] = "rt+jwt"
	if value, ok := realmConfig.Claims["iss"]; ok {
		expectedClaims["iss"] = value
	}
	if value, ok := realmConfig.Claims["aud"]; ok {
		expectedClaims["aud"] = value
	}
	var claims jwt.MapClaims
	if claims, err = auth.VerifyToken(tok.RefreshToken, realmConfig.VerificationPublicKey, expectedClaims); err != nil {
		clientID, _ := auth.UnverifiedTokenIdentity(tok.RefreshToken)
		tokenAuthFailureEvent(err).
			Str("realm", realm).
			Str("client_id", clientID).
			Msg("logout token authentication failed")
		c.StatusReply(w, 401, "invalid refresh token")
		return
	}
	err = c.repo.LogoutClient(claims, realm)
	if err != nil {
		clientID, _ := claims["client_id"].(string)
		event := log.Error().Err(err)
		if strings.Contains(err.Error(), "client id not found") || strings.Contains(err.Error(), "client_id claim is not valid") {
			event = log.Info().Err(err)
		}
		event.Str("realm", realm).Str("client_id", clientID).Msg("client logout failed")
		c.StatusReply(w, 500)
	} else {
		c.StatusReply(w, 200, "OK")
	}
}
