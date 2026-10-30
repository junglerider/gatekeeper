package client

// repository implementation for  database operations on client accounts

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"junglerider/gatekeeper/app"
	"junglerider/gatekeeper/auth"
	"junglerider/gatekeeper/utils"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jmoiron/sqlx"
	"github.com/rs/zerolog/log"
)

var errPasswordExpired = errors.New("password expired")
var errInvalidAPIKey = errors.New("invalid or expired API key")
var errClientCredentialsDenied = errors.New("access denied")
var errClientRefreshTokenReuse = errors.New("access denied - refresh token cannot be reused")

const apiKeyCacheMaxSize = 1000

// client repository interface
type ClientRepo interface {
	ListClients(realm string, isActive *bool, expiry *time.Time) ([]string, error)
	ReadClient(realm string, clientID string) (*Client, error)
	CreateClient(client Client, realm string) error
	UpdateClient(clientID string, realm string, props map[string]any) (int64, error)
	DeleteClient(clientID string, realm string) (int64, error)
	LoginClient(login *Client, config *app.Config) (*auth.TokenPair, error)
	VerifyAPIKey(apiKey string, realm string, config *app.Config) (map[string]any, error)
	RefreshToken(claims jwt.MapClaims, realm string, config *app.Config) (*auth.TokenPair, error)
	LogoutClient(claims jwt.MapClaims, realm string) error
}

// repository implementation
type Repo struct {
	db        *sqlx.DB
	dbName    string
	masterKey []byte
}

func NewRepo(db *sqlx.DB, dbName string, masterKey []byte) ClientRepo {
	return &Repo{db: db, dbName: dbName, masterKey: masterKey}
}

func (r *Repo) tableName(name string) string {
	if r.db.DriverName() == "pgx" || r.db.DriverName() == "postgres" {
		return name
	}
	return fmt.Sprintf("%s.%s", r.dbName, name)
}

// currentTimestamp returns the timestamp expression supported by the active SQL dialect.
func (r *Repo) currentTimestamp() string {
	if r.db.DriverName() == "pgx" || r.db.DriverName() == "postgres" {
		return "CURRENT_TIMESTAMP"
	}
	return "UTC_TIMESTAMP()"
}

// value type for TTL cache
type StrTTLVal struct {
	ClientID   string
	Realm      string
	AccessData *any
	Expiry     int64
}

var apiKeyCache = utils.NewCache[string, StrTTLVal]()

func apiKeyCacheKey(realm, apiKey string) string {
	return realm + ":" + apiKey
}

func invalidateAPIKeyCache(clientID, realm string) {
	for _, key := range apiKeyCache.Keys() {
		if entry, ok := apiKeyCache.Get(key); ok &&
			entry.ClientID == clientID &&
			(realm == "" || entry.Realm == realm) {
			apiKeyCache.Delete(key)
		}
	}
}

func ensureAPICacheCapacity() {
	if apiKeyCache.Len() < apiKeyCacheMaxSize {
		return
	}
	now := time.Now().Unix()
	keys := apiKeyCache.Keys()
	for _, key := range keys {
		if val, ok := apiKeyCache.Get(key); ok {
			if val.Expiry < now {
				apiKeyCache.Delete(key)
				return
			}
		}
	}
	if len(keys) > 0 {
		apiKeyCache.Delete(keys[0])
	}
}

// retrieves all client ids from the database
func (r *Repo) ListClients(realm string, isActive *bool, expiry *time.Time) ([]string, error) {
	var params []any
	whereClause := "realm = ?"
	params = append(params, realm)
	if isActive != nil {
		whereClause += " AND is_active = ?"
		params = append(params, *isActive)
	}
	if expiry != nil {
		whereClause += " AND pwd_expiry <= ?"
		params = append(params, *expiry)
	}
	query := fmt.Sprintf("SELECT client_id FROM %s WHERE %s ORDER BY client_id", r.tableName("clients"), whereClause)
	log.Trace().Str("sql", query).Msg("retrieving client list")
	// #nosec G701 - dynamic query with static parts and correctly bound data parameters
	rows, err := r.db.Query(r.db.Rebind(query), params...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var clients = make([]string, 0)
	for rows.Next() {
		var clientId string
		if err = rows.Scan(&clientId); err != nil {
			return nil, err
		}
		clients = append(clients, clientId)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return clients, nil
}

// retrieves a single client entity from the database
func (r *Repo) ReadClient(realm string, clientID string) (*Client, error) {
	query := fmt.Sprintf("SELECT * FROM %s WHERE client_id = ? AND realm = ?", r.tableName("clients"))
	log.Trace().Str("client_id", clientID).Str("sql", query).Msg("retrieving client")
	var client Client
	err := r.db.Get(&client, r.db.Rebind(query), clientID, realm)
	if err == nil {
		err = r.decryptAccess(&client)
	}
	if err != nil {
		return nil, err
	}
	return &client, nil
}

// inserts validated client entity into database
func (r *Repo) CreateClient(client Client, realm string) error {
	var err error
	if client.IsActive == nil {
		isActive := true
		client.IsActive = &isActive
	}
	client.Access, err = utils.JSONToStr(client.AccessData)
	if err != nil {
		return err
	}
	client.Password = auth.HashPassword(client.Password)
	client.APIKey = auth.HashAPIKey(client.APIKey, realm)
	owner := auth.OwnerContext("client", client.Realm, client.ClientID)
	dataKey, wrappedKey, err := auth.GenerateWrappedDataKey(r.masterKey, owner)
	if err != nil {
		return err
	}
	defer clear(dataKey)
	if client.Access != nil {
		encryptedAccess, err := auth.EncryptAccess(*client.Access, dataKey, owner)
		if err != nil {
			return err
		}
		client.Access = &encryptedAccess
	}
	client.EncKey = &wrappedKey
	query := fmt.Sprintf("INSERT INTO %s (client_id, realm, api_key, password, access, is_active, pwd_expiry, enc_key) VALUES (?,?,?,?,?,?,?,?)", r.tableName("clients"))
	log.Trace().Str("client_id", client.ClientID).Str("sql", query).Msg("creating client")
	_, err = r.db.Exec(r.db.Rebind(query), client.ClientID, client.Realm, client.APIKey, client.Password, client.Access, *client.IsActive, client.PwdExpiry, client.EncKey)
	return err
}

// updates a specific client entity in the database
func (r *Repo) UpdateClient(clientID string, realm string, props map[string]any) (int64, error) {
	if access, ok := props["access"]; ok && access != nil {
		accessJSON, ok := access.(string)
		if !ok {
			return 0, errors.New("access data must be a string")
		}
		owner := auth.OwnerContext("client", realm, clientID)
		var wrappedKey string
		query := fmt.Sprintf("SELECT enc_key FROM %s WHERE client_id = ? AND realm = ?", r.tableName("clients"))
		if err := r.db.QueryRowx(r.db.Rebind(query), clientID, realm).Scan(&wrappedKey); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return 0, nil
			}
			return 0, err
		}
		dataKey, err := auth.UnwrapDataKey(wrappedKey, r.masterKey, owner)
		if err != nil {
			return 0, err
		}
		defer clear(dataKey)
		encryptedAccess, err := auth.EncryptAccess(accessJSON, dataKey, owner)
		if err != nil {
			return 0, err
		}
		props["access"] = encryptedAccess
	}
	var columns []string
	var params []any
	query := fmt.Sprintf("UPDATE %s SET ", r.tableName("clients"))
	for k, v := range props {
		if v == nil {
			columns = append(columns, k+" = NULL")
		} else {
			columns = append(columns, k+" = ?")
			params = append(params, v)
		}
	}
	query += strings.Join(columns, ", ")
	query += ", updated_at = " + r.currentTimestamp() + " WHERE client_id = ? AND realm = ?"
	params = append(params, clientID, realm)
	log.Trace().Str("client_id", clientID).Str("sql", query).Msg("updating client")
	// #nosec G701 - dynamic query with static parts and correctly bound data parameters
	result, err := r.db.Exec(r.db.Rebind(query), params...)
	if err != nil {
		return 0, err
	}
	invalidateAPIKeyCache(clientID, realm)
	if updatedRows, err := result.RowsAffected(); err != nil {
		return 0, err
	} else {
		return updatedRows, nil
	}
}

// removes a client entity (or multiple entities with the same client id) from the database
func (r *Repo) DeleteClient(clientID string, realm string) (int64, error) {
	params := []any{clientID}
	query := fmt.Sprintf("DELETE FROM %s WHERE client_id = ?", r.tableName("clients"))
	if realm != "" {
		query += " AND realm = ?"
		params = append(params, realm)
	}
	log.Trace().Str("client_id", clientID).Str("sql", query).Msg("deleting client(s)")
	// #nosec G701 - dynamic query with static parts and correctly bound data parameters
	result, err := r.db.Exec(r.db.Rebind(query), params...)
	if err != nil {
		return 0, err
	}
	invalidateAPIKeyCache(clientID, realm)
	if deletedRows, err := result.RowsAffected(); err != nil {
		return 0, err
	} else {
		return deletedRows, nil
	}
}

// performs login and create a JWT token pair
func (r *Repo) LoginClient(login *Client, config *app.Config) (*auth.TokenPair, error) {
	query := fmt.Sprintf("SELECT * FROM %s WHERE client_id = ? AND realm = ? AND is_active = true", r.tableName("clients"))
	log.Trace().Str("client_id", login.ClientID).Str("sql", query).Msg("looking up client")
	row := r.db.QueryRowx(r.db.Rebind(query), login.ClientID, login.Realm)
	var client Client
	err := row.StructScan(&client)
	if err != nil {
		if err == sql.ErrNoRows {
			err = errClientCredentialsDenied
		}
		return nil, err
	}
	if client.IsActive != nil && !*client.IsActive {
		return nil, errClientCredentialsDenied
	}
	if !auth.VerifyPassword(client.Password, login.Password) {
		return nil, errClientCredentialsDenied
	}
	if client.PwdExpiry != nil && client.PwdExpiry.Before(time.Now()) {
		return nil, errPasswordExpired
	}
	if err = r.decryptAccess(&client); err != nil {
		return nil, err
	}
	overrideClaims := make(map[string]any)
	if client.AccessData != nil {
		overrideClaims["access"] = *client.AccessData
	}
	var tp *auth.TokenPair
	var refreshJTI string
	tp, refreshJTI, err = auth.CreateTokenPair(&client, overrideClaims, *config)
	if err != nil {
		return nil, err
	}
	issuedAt := time.Now().Unix()
	query = fmt.Sprintf("UPDATE %s SET last_login = ?, last_refresh = ?, jti_refresh = ? WHERE client_id = ? AND realm = ?", r.tableName("clients"))
	if _, err := r.db.Exec(r.db.Rebind(query), issuedAt, issuedAt, refreshJTI, login.ClientID, login.Realm); err != nil {
		return nil, err
	}
	return tp, nil
}

// verifies an API key against the cache or DB
func (r *Repo) VerifyAPIKey(apiKey string, realm string, config *app.Config) (map[string]any, error) {
	claims := make(map[string]any, len(config.Realms[realm].Claims)+2)
	for key, value := range config.Realms[realm].Claims {
		claims[key] = value
	}
	cacheKey := apiKeyCacheKey(realm, apiKey)
	if val, ok := apiKeyCache.Get(cacheKey); ok {
		if val.Expiry >= time.Now().Unix() {
			claims["client_id"] = val.ClientID
			if val.AccessData != nil {
				claims["access"] = *val.AccessData
			}
			return claims, nil
		}
	}
	hashedAPIKey := auth.HashAPIKey(&apiKey, realm)
	query := fmt.Sprintf("SELECT client_id, access, enc_key, is_active FROM %s WHERE api_key = ?", r.tableName("clients"))
	log.Trace().Str("api_key", *hashedAPIKey).Str("sql", query).Msg("retrieving client by API key")
	row := r.db.QueryRowx(r.db.Rebind(query), *hashedAPIKey)
	var clientId string
	var storedAccess, encKey sql.NullString
	var active sql.NullBool
	err := row.Scan(&clientId, &storedAccess, &encKey, &active)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errInvalidAPIKey
		}
		return nil, err
	}
	if active.Valid && !active.Bool {
		return nil, errInvalidAPIKey
	}
	client := Client{ClientID: clientId, Realm: realm}
	if storedAccess.Valid {
		client.Access = &storedAccess.String
	}
	if encKey.Valid {
		client.EncKey = &encKey.String
	}
	if err := r.decryptAccess(&client); err != nil {
		return nil, err
	}
	cacheEntry := StrTTLVal{
		ClientID:   clientId,
		Realm:      realm,
		AccessData: client.AccessData,
		Expiry:     time.Now().Unix() + int64(config.Server.ApiKeyCacheTTL),
	}
	ensureAPICacheCapacity()
	apiKeyCache.Set(cacheKey, cacheEntry)
	claims["client_id"] = clientId
	if client.AccessData != nil {
		claims["access"] = *client.AccessData
	}
	return claims, nil
}

// looks up client and creates a new access token
func (r *Repo) RefreshToken(claims jwt.MapClaims, realm string, config *app.Config) (*auth.TokenPair, error) {
	clientID, ok := claims["client_id"].(string)
	if !ok {
		return nil, errors.New("client_id claim is not valid")
	}
	jti, ok := claims["jti"].(string)
	if !ok || jti == "" {
		return nil, errors.New("jti claim is not valid")
	}
	query := fmt.Sprintf("SELECT * from %s WHERE client_id = ? AND realm = ?", r.tableName("clients"))
	row := r.db.QueryRowx(r.db.Rebind(query), clientID, realm)
	var client Client
	err := row.StructScan(&client)
	if err != nil {
		return nil, err
	}
	if client.IsActive != nil && !*client.IsActive {
		return nil, errClientCredentialsDenied
	}
	if client.PwdExpiry != nil && client.PwdExpiry.Before(time.Now()) {
		return nil, errPasswordExpired
	}
	if client.JTIRefresh == nil || *client.JTIRefresh != jti {
		return nil, errClientRefreshTokenReuse
	}
	if err = r.decryptAccess(&client); err != nil {
		return nil, err
	}
	overrideClaims := make(map[string]any, 2)
	overrideClaims["sid"] = claims["sid"]
	overrideClaims["sex"] = claims["sex"]
	if tp, refreshJTI, err := auth.CreateTokenPair(&client, overrideClaims, *config); err != nil {
		return nil, err
	} else {
		issuedAt := time.Now().Unix()
		query = fmt.Sprintf("UPDATE %s SET last_refresh = ?, jti_refresh = ? WHERE client_id = ? AND realm = ?", r.tableName("clients"))
		if _, err := r.db.Exec(r.db.Rebind(query), issuedAt, refreshJTI, clientID, realm); err != nil {
			return nil, err
		}
		return tp, nil
	}
}

func (r *Repo) decryptAccess(client *Client) error {
	if client.Access == nil {
		client.AccessData = nil
		return nil
	}
	if client.EncKey == nil {
		return errors.New("client encryption key is missing")
	}
	owner := auth.OwnerContext("client", client.Realm, client.ClientID)
	dataKey, err := auth.UnwrapDataKey(*client.EncKey, r.masterKey, owner)
	if err != nil {
		return err
	}
	defer clear(dataKey)
	accessJSON, err := auth.DecryptAccess(*client.Access, dataKey, owner)
	if err != nil {
		return err
	}
	client.AccessData, err = utils.StrToJSON(&accessJSON)
	return err
}

// clears last_refresh in database
func (r *Repo) LogoutClient(claims jwt.MapClaims, realm string) error {
	if clientID, ok := claims["client_id"].(string); !ok {
		return errors.New("client_id claim is not valid")
	} else {
		query := fmt.Sprintf("UPDATE %s SET last_refresh = NULL, jti_refresh = NULL WHERE client_id = ? AND realm = ?", r.tableName("clients"))
		result, err := r.db.Exec(r.db.Rebind(query), clientID, realm)
		if err != nil {
			return err
		}
		updatedRows, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if updatedRows == 0 {
			return errors.New("client id not found")
		}
	}
	return nil
}
