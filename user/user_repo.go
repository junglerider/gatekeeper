package user

// repository implementation for database operations on user accounts

import (
	"database/sql"
	"errors"
	"fmt"
	"sort"
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
var errOTPDenied = errors.New("OTP verification failed")
var errCredentialsDenied = errors.New("access denied")

// user repository interface
type UserRepo interface {
	ListUsers(realm string, clientID *string, isActive *bool, expiry *time.Time) ([]UserPK, error)
	ReadUser(u *UserPK) (*User, error)
	CreateUser(user User) error
	UpdateUser(u *UserPK, props map[string]any) (int64, error)
	DeleteUser(u *UserPK) (int64, error)
	LoginUser(login *User, config *app.Config) (*auth.TokenPair, error)
	RefreshToken(claims jwt.MapClaims, realm string, config *app.Config) (*auth.TokenPair, error)
	LogoutUser(claims jwt.MapClaims, realm string) error
	OTPLogin(realm string, login OTPLogin, config *app.Config) (*auth.TokenPair, error)
}

// repository implementation
type Repo struct {
	db        *sqlx.DB
	dbName    string
	masterKey []byte
}

func NewRepo(db *sqlx.DB, dbName string, masterKey []byte) UserRepo {
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

// retrieves filtered list of users from the database
func (r *Repo) ListUsers(realm string, clientID *string, isActive *bool, expiry *time.Time) ([]UserPK, error) {
	var params []any
	params = append(params, realm)
	whereClause := "realm = ?"
	if isActive != nil {
		whereClause += " AND is_active = ?"
		params = append(params, *isActive)
	}
	if clientID != nil {
		whereClause += " AND client_id = ?"
		params = append(params, *clientID)
	}
	if expiry != nil {
		whereClause += " AND pwd_expiry <= ?"
		params = append(params, *expiry)
	}
	query := fmt.Sprintf("SELECT client_id, name FROM %s WHERE %s ORDER BY client_id, name", r.tableName("users"), whereClause)
	log.Trace().Str("sql", query).Msg("retrieving user list")
	// #nosec G701 - dynamic query with static parts and correctly bound data parameters
	rows, err := r.db.Query(r.db.Rebind(query), params...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users = make([]UserPK, 0)
	for rows.Next() {
		entry := UserPK{}
		err = rows.Scan(&entry.ClientID, &entry.Name)
		if err != nil {
			return nil, err
		}
		users = append(users, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return users, nil
}

// retrieves user data from the database by realm, client id and name
func (r *Repo) ReadUser(u *UserPK) (*User, error) {
	query := fmt.Sprintf("SELECT * FROM %s WHERE client_id =? AND realm =? AND name =?", r.tableName("users"))
	log.Trace().Str("sql", query).Msg("retrieving user account")
	var user User
	err := r.db.Get(&user, r.db.Rebind(query), u.ClientID, u.Realm, u.Name)
	if err != nil {
		return nil, err
	}
	if err := r.decryptAccess(&user); err != nil {
		return nil, err
	}
	return &user, nil
}

// inserts validated user entity into database
func (r *Repo) CreateUser(user User) error {
	var otpSecret *string
	owner := auth.OwnerContext("user", user.Realm, user.ClientID, user.Name)
	dataKey, wrappedKey, err := auth.GenerateWrappedDataKey(r.masterKey, owner)
	if err != nil {
		return err
	}
	defer clear(dataKey)
	if user.OTPSecret != nil {
		encryptedSecret, err := auth.EncryptOTPSecret(*user.OTPSecret, dataKey, owner)
		if err != nil {
			return err
		}
		otpSecret = &encryptedSecret
	}
	if user.Access != nil {
		encryptedAccess, err := auth.EncryptAccess(*user.Access, dataKey, owner)
		if err != nil {
			return err
		}
		user.Access = &encryptedAccess
	}
	user.EncKey = &wrappedKey
	user.Password = auth.HashPassword(user.Password)
	query := fmt.Sprintf("INSERT INTO %s (client_id, realm, name, password, access, is_active, pwd_expiry, otp_enabled, otp_secret, enc_key) VALUES (?,?,?,?,?,?,?,?,?,?)", r.tableName("users"))
	log.Trace().Str("name", user.Name).Str("client_id", user.ClientID).Str("sql", query).Msg("creating user")
	_, err = r.db.Exec(r.db.Rebind(query), user.ClientID, user.Realm, user.Name, user.Password, user.Access, *user.IsActive, user.PwdExpiry, *user.OTPEnabled, otpSecret, user.EncKey)
	return err
}

// updates a user entity in the database
func (r *Repo) UpdateUser(u *UserPK, props map[string]any) (int64, error) {
	if err := r.prepareUserUpdates(u, props); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, nil
		}
		return 0, err
	}
	query, params := buildUserUpdateQuery(r.tableName("users"), r.currentTimestamp(), u, props)
	log.Trace().Interface("user", u).Str("sql", query).Msg("updating user")
	// #nosec G701 - dynamic query with static parts and correctly bound data parameters
	result, err := r.db.Exec(r.db.Rebind(query), params...)
	if err != nil {
		return 0, err
	}
	updatedRows, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	return updatedRows, nil
}

// prepareUserUpdates encrypts access data and OTP secrets and rebinds them when the owner changes.
func (r *Repo) prepareUserUpdates(u *UserPK, props map[string]any) error {
	newName, renaming := props["name"].(string)
	otpValue, hasOTPUpdate := props["otp_secret"]
	accessValue, hasAccessUpdate := props["access"]
	renaming = renaming && newName != u.Name
	if (!hasOTPUpdate || otpValue == nil) &&
		(!hasAccessUpdate || accessValue == nil) &&
		!renaming {
		return nil
	}

	oldOwner := auth.OwnerContext("user", u.Realm, u.ClientID, u.Name)
	newOwner := oldOwner
	if renaming && newName != u.Name {
		newOwner = auth.OwnerContext("user", u.Realm, u.ClientID, newName)
	}

	var wrappedKey string
	var storedSecret sql.NullString
	var storedAccess sql.NullString
	query := fmt.Sprintf("SELECT enc_key, access, otp_secret FROM %s WHERE client_id = ? AND realm = ? AND name = ?", r.tableName("users"))
	if err := r.db.QueryRowx(r.db.Rebind(query), u.ClientID, u.Realm, u.Name).Scan(&wrappedKey, &storedAccess, &storedSecret); err != nil {
		return err
	}
	if wrappedKey == "" {
		return errors.New("user encryption key is missing")
	}
	dataKey, err := auth.UnwrapDataKey(wrappedKey, r.masterKey, oldOwner)
	if err != nil {
		return err
	}
	defer clear(dataKey)

	// Ciphertext and its wrapped data key are both bound to the owner's identity.
	if newOwner != oldOwner {
		wrappedKey, err = auth.WrapDataKey(dataKey, r.masterKey, newOwner)
		if err != nil {
			return err
		}
		props["enc_key"] = wrappedKey
	}
	if hasAccessUpdate {
		if accessValue == nil {
			props["access"] = nil
		} else if access, ok := accessValue.(string); !ok {
			return errors.New("access data must be a string")
		} else {
			encryptedAccess, err := auth.EncryptAccess(access, dataKey, newOwner)
			if err != nil {
				return err
			}
			props["access"] = encryptedAccess
		}
	} else if renaming && storedAccess.Valid {
		access, err := auth.DecryptAccess(storedAccess.String, dataKey, oldOwner)
		if err != nil {
			return err
		}
		encryptedAccess, err := auth.EncryptAccess(access, dataKey, newOwner)
		if err != nil {
			return err
		}
		props["access"] = encryptedAccess
	}
	return r.updateOTPSecret(props, otpValue, hasOTPUpdate, storedSecret, dataKey, oldOwner, newOwner)
}

func (r *Repo) updateOTPSecret(props map[string]any, otpValue any, hasOTPUpdate bool, storedSecret sql.NullString, dataKey []byte, oldOwner, newOwner string) error {
	if hasOTPUpdate && otpValue == nil {
		props["otp_secret"] = nil
		return nil
	}

	secret, err := resolveOTPSecret(otpValue, hasOTPUpdate, storedSecret, dataKey, oldOwner)
	if err != nil || secret == "" {
		return err
	}
	encryptedSecret, err := auth.EncryptOTPSecret(secret, dataKey, newOwner)
	if err != nil {
		return err
	}
	props["otp_secret"] = encryptedSecret
	return nil
}

func resolveOTPSecret(otpValue any, hasOTPUpdate bool, storedSecret sql.NullString, dataKey []byte, oldOwner string) (string, error) {
	if hasOTPUpdate {
		secret, ok := otpValue.(string)
		if !ok {
			return "", errors.New("OTP secret must be a string")
		}
		return secret, nil
	}
	if !storedSecret.Valid {
		return "", nil
	}
	return auth.DecryptOTPSecret(storedSecret.String, dataKey, oldOwner)
}

func (r *Repo) decryptAccess(user *User) error {
	if user.Access == nil {
		user.AccessData = nil
		return nil
	}
	if user.EncKey == nil {
		return errors.New("user encryption key is missing")
	}
	owner := auth.OwnerContext("user", user.Realm, user.ClientID, user.Name)
	dataKey, err := auth.UnwrapDataKey(*user.EncKey, r.masterKey, owner)
	if err != nil {
		return err
	}
	defer clear(dataKey)
	accessJSON, err := auth.DecryptAccess(*user.Access, dataKey, owner)
	if err != nil {
		return err
	}
	user.AccessData, err = utils.StrToJSON(&accessJSON)
	return err
}

func buildUserUpdateQuery(table, currentTimestamp string, u *UserPK, props map[string]any) (string, []any) {
	var columns []string
	var params []any
	// Sorting keeps generated SQL and bound arguments deterministic for logs and tests.
	keys := make([]string, 0, len(props))
	for k := range props {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := props[k]
		if v == nil {
			columns = append(columns, k+" = NULL")
		} else {
			columns = append(columns, k+" = ?")
			params = append(params, v)
		}
	}
	query := fmt.Sprintf("UPDATE %s SET ", table)
	query += strings.Join(columns, ", ")
	query += ", updated_at = " + currentTimestamp + " WHERE client_id = ? AND realm = ? AND name = ?"
	params = append(params, u.ClientID, u.Realm, u.Name)
	return query, params
}

// removes a user entity from the database and returns number of deleted rows
func (r *Repo) DeleteUser(u *UserPK) (int64, error) {
	query := fmt.Sprintf("DELETE FROM %s WHERE client_id = ? AND realm = ? AND name = ?", r.tableName("users"))
	log.Trace().Interface("user", u).Str("sql", query).Msg("deleting user")
	// #nosec G701 - dynamic query with static table name
	if result, err := r.db.Exec(r.db.Rebind(query), u.ClientID, u.Realm, u.Name); err != nil {
		return 0, err
	} else if deletedRows, err := result.RowsAffected(); err != nil {
		return 0, err
	} else {
		return deletedRows, nil
	}
}

// performs a user login with credentials and returns a pair of JSON web tokens
func (r *Repo) LoginUser(login *User, config *app.Config) (*auth.TokenPair, error) {
	query := fmt.Sprintf("SELECT * FROM %s WHERE client_id = ? AND realm = ? AND name = ? AND is_active = true", r.tableName("users"))
	log.Trace().Interface("user", login).Str("sql", query).Msg("looking up user")
	var user User
	err := r.db.Get(&user, r.db.Rebind(query), login.ClientID, login.Realm, login.Name)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("%w: user is not known", errCredentialsDenied)
		}
		return nil, err
	}
	if !auth.VerifyPassword(user.Password, login.Password) {
		return nil, fmt.Errorf("%w: password invalid", errCredentialsDenied)
	}
	if user.PwdExpiry != nil && user.PwdExpiry.Before(time.Now()) {
		return nil, errPasswordExpired
	}
	if user.OTPEnabled != nil && *user.OTPEnabled {
		if user.OTPSecret == nil || user.EncKey == nil {
			return nil, errors.New("OTP is enabled but not configured")
		}
		challengeToken, err := auth.CreateChallengeToken(&user, *config)
		if err != nil {
			return nil, err
		}
		return &auth.TokenPair{AccessToken: challengeToken}, nil
	}
	overrideClaims := make(map[string]any, 3)
	if err = r.decryptAccess(&user); err != nil {
		return nil, err
	}
	if user.AccessData != nil {
		overrideClaims["access"] = *user.AccessData
	}
	overrideClaims["iat"] = time.Now().Unix()

	var tp *auth.TokenPair
	var refreshJTI string

	tp, refreshJTI, err = auth.CreateTokenPair(&user, overrideClaims, *config)
	if err != nil {
		return nil, err
	}
	query = fmt.Sprintf("UPDATE %s SET last_login = ?, last_refresh = ?, jti_refresh = ? WHERE client_id = ? AND realm = ? AND name = ?", r.tableName("users"))
	if _, err := r.db.Exec(r.db.Rebind(query), overrideClaims["iat"], overrideClaims["iat"], refreshJTI, login.ClientID, login.Realm, login.Name); err != nil {
		return nil, err
	}
	return tp, nil
}

// looks up user and creates a new access token
func (r *Repo) RefreshToken(claims jwt.MapClaims, realm string, config *app.Config) (*auth.TokenPair, error) {
	var clientID, name string
	var ok bool
	if clientID, ok = claims["client_id"].(string); !ok {
		return nil, errors.New("access denied - client_id claim is not valid")
	}
	if name, ok = claims["sub"].(string); !ok {
		return nil, errors.New("access denied - sub claim is not valid")
	}
	jti, ok := claims["jti"].(string)
	if !ok || jti == "" {
		return nil, errors.New("access denied - jti claim is not valid")
	}
	query := fmt.Sprintf("SELECT * from %s WHERE client_id = ? AND realm = ? AND name = ?", r.tableName("users"))
	var user User
	err := r.db.Get(&user, r.db.Rebind(query), clientID, realm, name)
	if err != nil {
		return nil, err
	}
	if user.IsActive != nil && !*user.IsActive {
		return nil, errors.New("access denied - user is not active")
	}
	if user.PwdExpiry != nil && user.PwdExpiry.Before(time.Now()) {
		return nil, errPasswordExpired
	}
	if err = r.decryptAccess(&user); err != nil {
		return nil, err
	}
	if iat, ok := claims["iat"].(float64); !ok {
		return nil, errors.New("issued at claim is not valid")
	} else if user.LastRefresh == nil || int64(iat) != *user.LastRefresh {
		return nil, errors.New("access denied - token cannot be reused")
	}
	if user.JTIRefresh == nil || *user.JTIRefresh != jti {
		return nil, errors.New("access denied - refresh token cannot be reused")
	}
	overrideClaims := make(map[string]any, 2)
	overrideClaims["sid"] = claims["sid"]
	overrideClaims["sex"] = claims["sex"]
	overrideClaims["iat"] = time.Now().Unix()
	if tp, refreshJTI, err := auth.CreateTokenPair(&user, overrideClaims, *config); err != nil {
		return nil, err
	} else {
		query = fmt.Sprintf("UPDATE %s SET last_refresh = ?, jti_refresh = ? WHERE client_id = ? AND realm = ? AND name = ?", r.tableName("users"))
		if _, err := r.db.Exec(r.db.Rebind(query), overrideClaims["iat"], refreshJTI, clientID, realm, name); err != nil {
			return nil, err
		}
		return tp, nil
	}
}

// clears last_refresh in database
func (r *Repo) LogoutUser(claims jwt.MapClaims, realm string) error {
	var clientID, name string
	var ok bool
	if clientID, ok = claims["client_id"].(string); !ok {
		return errors.New("client_id claim is not valid")
	}
	if name, ok = claims["sub"].(string); !ok {
		return errors.New("sub claim is not valid")
	}
	query := fmt.Sprintf("UPDATE %s SET last_refresh = NULL, jti_refresh = NULL WHERE client_id = ? AND realm = ? AND name = ?", r.tableName("users"))
	result, err := r.db.Exec(r.db.Rebind(query), clientID, realm, name)
	if err != nil {
		return err
	} else {
		if updatedRows, _ := result.RowsAffected(); updatedRows == 0 {
			return errors.New("user not found")
		}
	}
	return nil
}

// looks up OTP secret and verifies given OTP credentials
func (r *Repo) OTPLogin(realm string, login OTPLogin, config *app.Config) (*auth.TokenPair, error) {
	query := fmt.Sprintf("SELECT * from %s WHERE client_id = ? AND realm = ? AND name = ? AND is_active = true", r.tableName("users"))
	var user User
	err := r.db.Get(&user, r.db.Rebind(query), login.ClientID, realm, login.Name)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errOTPDenied
		}
		return nil, err
	}
	if user.OTPEnabled == nil || !*user.OTPEnabled || user.OTPSecret == nil {
		return nil, errOTPDenied
	}
	if user.EncKey == nil {
		return nil, errOTPDenied
	}
	if user.PwdExpiry != nil && user.PwdExpiry.Before(time.Now()) {
		return nil, errPasswordExpired
	}
	owner := auth.OwnerContext("user", realm, login.ClientID, login.Name)
	dataKey, err := auth.UnwrapDataKey(*user.EncKey, r.masterKey, owner)
	if err != nil {
		return nil, errOTPDenied
	}
	defer clear(dataKey)
	secret, err := auth.DecryptOTPSecret(*user.OTPSecret, dataKey, owner)
	if err != nil {
		return nil, errOTPDenied
	}
	if !auth.VerifyOTP(login.OTP, secret) {
		return nil, errOTPDenied
	}
	if err = r.decryptAccess(&user); err != nil {
		return nil, err
	}
	loginTime := time.Now().Unix()
	overrideClaims := map[string]any{"iat": loginTime}
	tp, refreshJTI, err := auth.CreateTokenPair(&user, overrideClaims, *config)
	if err != nil {
		return nil, err
	}
	query = fmt.Sprintf("UPDATE %s SET last_login = ?, last_refresh = ?, jti_refresh = ? WHERE client_id = ? AND realm = ? AND name = ?", r.tableName("users"))
	// #nosec G701 - dynamic query with static parts and correctly bound data parameters
	if _, err := r.db.Exec(r.db.Rebind(query), loginTime, loginTime, refreshJTI, login.ClientID, realm, login.Name); err != nil {
		return nil, err
	}
	return tp, nil
}
