package user

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
	"github.com/rs/zerolog/log"
)

type Controller struct {
	*app.BaseController
	repo UserRepo
}

func NewController(repo UserRepo, config *app.Config) *Controller {
	return &Controller{
		&app.BaseController{Config: config},
		repo,
	}
}

// registers all user routes
func (c *Controller) RegisterRoutes(public chi.Router, protected chi.Router) {
	protected.Get("/users", c.listHandler)
	protected.Get("/users/{clientId}/{name}", c.readHandler)
	protected.Post("/users", c.createHandler)
	protected.Patch("/users/{clientId}/{name}", c.updateHandler)
	protected.Delete("/users/{clientId}/{name}", c.deleteHandler)
	public.Post("/users/login", c.loginHandler)
	public.Post("/users/otp/login", c.otpLoginHandler)
	public.Post("/users/auth", c.authHandler)
	public.Post("/users/refresh", c.refreshHandler)
	public.Post("/users/logout", c.logoutHandler)
}

// retrieves list of users
func (c *Controller) listHandler(w http.ResponseWriter, r *http.Request) {
	realm := c.DefaultRealm(r.URL.Query().Get("realm"))
	var isActive *bool
	if isActiveParam, err := strconv.ParseBool(r.URL.Query().Get("isActive")); err == nil {
		isActive = &isActiveParam
	}
	var clientID *string
	if clientIDParam := r.URL.Query().Get("clientId"); clientIDParam != "" {
		clientID = &clientIDParam
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
	err := errors.Join(c.ValidateStringPtr(clientID, "client id", 0, 16, false), c.ValidateRealm(realm))
	if err != nil {
		c.StatusReply(w, 400, err.Error())
		return
	}
	var users []UserPK
	users, err = c.repo.ListUsers(realm, clientID, isActive, expiry)
	if err != nil {
		log.Error().Err(err).Msg("cannot retrieve list of user accounts:")
		c.StatusReply(w, 500)
		return
	}
	c.DataReply(w, 200, users)
}

// retrieves user data for a single user with its access object
func (c *Controller) readHandler(w http.ResponseWriter, r *http.Request) {
	u, err := getUserPK(c, r)
	if err != nil {
		c.StatusReply(w, 400, err.Error())
		return
	}
	user, err := c.repo.ReadUser(u)
	if err != nil {
		if err == sql.ErrNoRows {
			c.StatusReply(w, 404)
		} else {
			log.Error().Interface("user", u).Err(err).Msg("cannot read user account:")
			c.StatusReply(w, 500)
		}
		return
	}
	if user.Password != nil {
		*user.Password = "*****"
	}
	if user.OTPSecret != nil {
		*user.OTPSecret = "*****"
	}
	c.DataReply(w, 200, user)
}

// creates a new user account
func (c *Controller) createHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err == nil {
		user.Realm = c.DefaultRealm(user.Realm)
		minPasswordLength := c.MinPasswordLength(user.Realm)
		err = errors.Join(
			c.ValidateRealm(user.Realm),
			c.ValidateString(user.ClientID, "client id", 1, 16, true),
			c.ValidateString(user.Name, "name", 1, 255, true),
			c.ValidateStringPtr(user.Password, "password", minPasswordLength, 64, true),
			c.ValidateStringPtr(user.OTPSecret, "OTP secret", 16, 32, false),
		)
	}
	if err == nil {
		user.Access, err = utils.JSONToStr(user.AccessData)
	}
	if err != nil {
		c.StatusReply(w, 400, err.Error())
		return
	}
	if user.IsActive == nil {
		isActive := true
		user.IsActive = &isActive
	}
	if user.OTPEnabled == nil {
		otpEnabled := false
		user.OTPEnabled = &otpEnabled
	}
	err = c.repo.CreateUser(user)
	if err != nil {
		log.Error().Str("clientId", user.ClientID).Str("name", user.Name).Err(err).Msg("cannot create user account:")
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") {
			c.StatusReply(w, 409, err.Error())
		} else {
			c.StatusReply(w, 500)
		}
		return
	}
	var response = map[string]any{
		"message":  "created",
		"realm":    user.Realm,
		"clientId": user.ClientID,
		"name":     user.Name,
	}
	c.DataReply(w, 201, response)
}

// updates a given user account
func (c *Controller) updateHandler(w http.ResponseWriter, r *http.Request) {
	var props map[string]any
	u, err := getUserPK(c, r)
	if err == nil {
		props, err = readUpdateProps(c, r, u.Realm)
	}
	if err != nil {
		c.StatusReply(w, 400, err.Error())
		return
	}
	updatedRows, err := c.repo.UpdateUser(u, props)
	if err != nil {
		log.Error().Interface("user", u).Err(err).Msg("cannot update user account:")
		c.StatusReply(w, 500)
	} else if updatedRows == 0 {
		c.StatusReply(w, 404)
	} else {
		w.WriteHeader(204)
	}
}

// reads the user update properties from the request body
func readUpdateProps(c *Controller, r *http.Request, realm string) (map[string]any, error) {
	props := make(map[string]any, 6)
	input := make(map[string]any)
	err := json.NewDecoder(r.Body).Decode(&input)
	if err != nil {
		return props, err
	}
	for k, v := range input {
		switch k {
		case "password":
			if s, ok := v.(string); ok {
				err = c.ValidateString(s, k, c.MinPasswordLength(realm), 64, true)
				props[k] = auth.HashPassword(&s)
			}
		case "name":
			if s, ok := v.(string); ok {
				err = c.ValidateString(s, k, 1, 255, false)
				props[k] = s
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
		case "isActive":
			if b, ok := v.(bool); ok {
				props["is_active"] = b
			} else {
				err = errors.New("isActive must be of type boolean")
			}
		case "otpEnabled":
			if b, ok := v.(bool); ok {
				props["otp_enabled"] = b
			} else {
				err = errors.New("optEnabled must be of type boolean")
			}
		case "otpSecret":
			if s, ok := v.(string); ok {
				err = c.ValidateString(s, k, 16, 32, false)
				props["otp_secret"] = s
			} else if v == nil {
				props["otp_secret"] = nil
			} else {
				err = errors.New("otpSecret must be a string")
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

// deletes a user account
func (c *Controller) deleteHandler(w http.ResponseWriter, r *http.Request) {
	u, err := getUserPK(c, r)
	if err != nil {
		c.StatusReply(w, 400, err.Error())
		return
	}
	deletedRows, err := c.repo.DeleteUser(u)
	if err != nil {
		log.Error().Interface("user", u).Err(err).Msg("cannot delete user account:")
		c.StatusReply(w, 500)
	} else if deletedRows == 0 {
		c.StatusReply(w, 404)
	} else {
		w.WriteHeader(204)
	}
}

// retrieves three primary key properties from request URL
func getUserPK(c *Controller, r *http.Request) (*UserPK, error) {
	var u UserPK
	u.Realm = c.DefaultRealm(r.URL.Query().Get("realm"))
	u.ClientID = chi.URLParam(r, "clientId")
	u.Name = chi.URLParam(r, "name")
	err := errors.Join(
		c.ValidateRealm(u.Realm),
		c.ValidateString(u.ClientID, "client id", 1, 16, true),
		c.ValidateString(u.Name, "name", 1, 255, true),
	)
	return &u, err
}

// JWT login with a user account
func (c *Controller) loginHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	var tokenPair *auth.TokenPair
	err := json.NewDecoder(r.Body).Decode(&user)
	user.Realm = c.DefaultRealm(r.URL.Query().Get("realm"))
	if err == nil {
		err = errors.Join(
			c.ValidateString(user.ClientID, "client id", 1, 16, true),
			c.ValidateStringPtr(user.Password, "password", 1, 64, true),
			c.ValidateString(user.Name, "name", 1, 255, true),
			c.ValidateRealm(user.Realm),
		)
	}
	if err != nil {
		c.StatusReply(w, 400, err.Error())
		return
	}
	tokenPair, err = c.repo.LoginUser(&user, c.Config)
	if err != nil {
		log.Error().Err(err).Msg("login failed")
		if errors.Is(err, errPasswordExpired) {
			c.StatusReply(w, 401, errPasswordExpired.Error())
		} else if errors.Is(err, errCredentialsDenied) || strings.Contains(err.Error(), "access denied") {
			c.StatusReply(w, 401, "credentials not recognised")
		} else {
			c.StatusReply(w, 500)
		}
		return
	}
	c.DataReply(w, 200, tokenPair)
}

// authenticates a user's JWT token
func (c *Controller) authHandler(w http.ResponseWriter, r *http.Request) {
	realm := c.DefaultRealm(r.URL.Query().Get("realm"))
	var creds auth.Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err == nil {
		err = c.ValidateRealm(realm)
	}
	if err != nil {
		c.StatusReply(w, 400, err.Error())
		return
	}
	var claims jwt.MapClaims
	if creds.AccessToken == "" {
		log.Debug().Msg("no token provided")
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
			log.Debug().Err(err).Msg("invalid JWT access token")
			c.StatusReply(w, 401, "invalid or expired access token")
			return
		}
	}
	c.DataReply(w, 200, claims)
}

// refreshes access token using refresh token
func (c *Controller) refreshHandler(w http.ResponseWriter, r *http.Request) {
	realm := c.DefaultRealm(r.URL.Query().Get("realm"))
	var tok auth.TokenPair
	err := json.NewDecoder(r.Body).Decode(&tok)
	if err == nil {
		err = c.ValidateRealm(realm)
	}
	if tok.RefreshToken == "" {
		err = errors.New("refresh token is required")
	}
	if err != nil {
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
		log.Debug().Err(err).Msg("invalid JWT refresh token")
		c.StatusReply(w, 401, "invalid refresh token")
		return
	}
	tokenPair, err := c.repo.RefreshToken(claims, realm, c.Config)
	if err != nil {
		log.Error().Err(err).Msg("failed to refresh token")
		switch {
		case strings.Contains(err.Error(), "refresh token cannot be reused"), strings.Contains(err.Error(), "token cannot be reused"):
			c.StatusReply(w, 401, "refresh token cannot be reused")
		case strings.Contains(err.Error(), "access denied"):
			c.StatusReply(w, 401, "refresh token claims invalid")
		default:
			c.StatusReply(w, 500)
		}
		return
	}
	c.DataReply(w, 200, tokenPair)
}

// logs user out
func (c *Controller) logoutHandler(w http.ResponseWriter, r *http.Request) {
	realm := c.DefaultRealm(r.URL.Query().Get("realm"))
	var tok auth.TokenPair
	err := json.NewDecoder(r.Body).Decode(&tok)
	if err == nil {
		err = c.ValidateRealm(realm)
	}
	if tok.RefreshToken == "" {
		err = errors.New("refresh token is required")
	}
	if err != nil {
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
		log.Debug().Err(err).Msg("invalid JWT refresh token")
		c.StatusReply(w, 401, "invalid refresh token")
		return
	}
	err = c.repo.LogoutUser(claims, realm)
	if err != nil {
		log.Error().Err(err).Msg("failed to logout")
		c.StatusReply(w, 500)
	} else {
		c.StatusReply(w, 200, "OK")
	}
}

// performs an OTP login/verification
func (c *Controller) otpLoginHandler(w http.ResponseWriter, r *http.Request) {
	realm := c.DefaultRealm(r.URL.Query().Get("realm"))
	var login OTPLogin
	err := json.NewDecoder(r.Body).Decode(&login)
	if err == nil {
		err = errors.Join(
			c.ValidateString(login.ChallengeToken, "challenge token", 1, 4096, true),
			c.ValidateString(login.OTP, "otp", 6, 6, true),
			c.ValidateRealm(realm),
		)
	}
	if err != nil {
		c.StatusReply(w, 400, err.Error())
		return
	}
	realmConfig := c.Config.Realms[realm]
	claims, err := auth.VerifyChallengeToken(login.ChallengeToken, realmConfig.VerificationPublicKey, realm)
	if err != nil {
		log.Debug().Err(err).Msg("invalid OTP challenge token")
		c.StatusReply(w, 401, "invalid or expired challenge token")
		return
	}
	login.ClientID = claims["client_id"].(string)
	login.Name = claims["sub"].(string)
	tokenPair, err := c.repo.OTPLogin(realm, login, c.Config)
	if err != nil {
		log.Error().Err(err).Msg("otp login failed")
		if errors.Is(err, errOTPDenied) || errors.Is(err, errPasswordExpired) {
			c.StatusReply(w, 401, "invalid challenge or OTP")
		} else {
			c.StatusReply(w, 500)
		}
		return
	}
	c.DataReply(w, 200, tokenPair)
}
