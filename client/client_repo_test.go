package client

import (
	"bytes"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"junglerider/gatekeeper/auth"
	"testing"
	"time"

	"junglerider/gatekeeper/app"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"

	"github.com/DATA-DOG/go-sqlmock"
)

var repoTestMasterKey = bytes.Repeat([]byte{0x42}, 32)

func testSigningKeys(seedByte byte) (string, string) {
	seed := bytes.Repeat([]byte{seedByte}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	return base64.StdEncoding.EncodeToString(seed),
		base64.StdEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey))
}

// Helper function to create a pointer to a value
func PtrFacade[T any](val T) *T {
	return &val
}

func encryptedAccessFixture(t *testing.T, realm, clientID, access string) (string, string) {
	t.Helper()
	owner := auth.OwnerContext("client", realm, clientID)
	dataKey, wrappedKey, err := auth.GenerateWrappedDataKey(repoTestMasterKey, owner)
	assert.NoError(t, err)
	encrypted, err := auth.EncryptAccess(access, dataKey, owner)
	assert.NoError(t, err)
	clear(dataKey)
	return encrypted, wrappedKey
}

func setupConfig() *app.Config {
	signingPrivateKey, verificationPublicKey := testSigningKeys(1)
	config := &app.Config{
		Realms: map[string]app.RealmConfig{
			"api": {
				SigningPrivateKey:     signingPrivateKey,
				VerificationPublicKey: verificationPublicKey,
				AccessTokenLifetime:   3600,
				RefreshTokenLifetime:  7200,
				SessionMaxLifetime:    86400,
				Claims:                map[string]any{"iss": "myIssuer"},
			},
		},
		Server: app.Config{}.Server,
	}
	return config
}

type NonJSONSerializable struct {
	Data func() // Functions cannot be serialized to JSON
}

func TestListClients(t *testing.T) {
	const listQuery = "^SELECT client_id FROM [\\w_]*.clients WHERE realm = \\? ORDER BY client_id$"
	const filteredListQuery = "^SELECT client_id FROM [\\w_]*.clients WHERE realm = \\? AND is_active = \\? ORDER BY client_id$"
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close()
	sqlxDB := sqlx.NewDb(db, "mysql")
	repo := &Repo{db: sqlxDB}

	t.Run("Successful list", func(t *testing.T) {
		rows := sqlmock.NewRows([]string{"client_id"}).AddRow("client-1").AddRow("client-2").AddRow("client-3")
		mock.ExpectQuery(listQuery).WithArgs("api").WillReturnRows(rows)

		clients, err := repo.ListClients("api", nil, nil)
		assert.NoError(t, err)
		assert.Equal(t, []string{"client-1", "client-2", "client-3"}, clients)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Successful filtered list", func(t *testing.T) {
		active := true
		rows := sqlmock.NewRows([]string{"client_id"}).AddRow("client-1").AddRow("client-3")
		mock.ExpectQuery(filteredListQuery).WithArgs("api", active).WillReturnRows(rows)

		clients, err := repo.ListClients("api", &active, nil)
		assert.NoError(t, err)
		assert.Equal(t, []string{"client-1", "client-3"}, clients)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Expiry filtered list", func(t *testing.T) {
		expiry := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
		rows := sqlmock.NewRows([]string{"client_id"}).AddRow("client-1")
		mock.ExpectQuery("^SELECT client_id FROM [\\w_]*.clients WHERE realm = \\? AND pwd_expiry <= \\? ORDER BY client_id$").
			WithArgs("api", expiry).
			WillReturnRows(rows)

		clients, err := repo.ListClients("api", nil, &expiry)
		assert.NoError(t, err)
		assert.Equal(t, []string{"client-1"}, clients)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("DB error", func(t *testing.T) {
		mock.ExpectQuery(listQuery).WithArgs("api").WillReturnError(errors.New("db error"))

		clients, err := repo.ListClients("api", nil, nil)
		assert.Error(t, err)
		assert.Nil(t, clients)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Scan error", func(t *testing.T) {
		rows := sqlmock.NewRows([]string{"client_id"}).AddRow(nil)
		mock.ExpectQuery(listQuery).WithArgs("api").WillReturnRows(rows)

		clients, err := repo.ListClients("api", nil, nil)
		assert.Error(t, err)
		assert.Nil(t, clients)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// TestListClients_PostgresRebindsPlaceholdersAndUsesCurrentSchema checks PostgreSQL query formatting.
func TestListClients_PostgresRebindsPlaceholdersAndUsesCurrentSchema(t *testing.T) {
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close()
	repo := &Repo{db: sqlx.NewDb(db, "pgx"), dbName: "testdb"}
	mock.ExpectQuery("^SELECT client_id FROM clients WHERE realm = \\$1 ORDER BY client_id$").
		WithArgs("api").
		WillReturnRows(sqlmock.NewRows([]string{"client_id"}))

	clients, err := repo.ListClients("api", nil, nil)
	assert.NoError(t, err)
	assert.Empty(t, clients)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestReadClient(t *testing.T) {
	const readQuery = "SELECT \\* FROM [\\w_]*.clients WHERE client_id = \\? AND realm = \\?"
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close()
	sqlxDB := sqlx.NewDb(db, "mysql")
	repo := &Repo{db: sqlxDB, masterKey: repoTestMasterKey}

	t.Run("Successful read", func(t *testing.T) {
		access, encKey := encryptedAccessFixture(t, "api", "client-1", `{"key":"value"}`)
		createdAt := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
		updatedAt := time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC)
		rows := sqlmock.NewRows([]string{"client_id", "realm", "password", "api_key", "access", "last_login", "last_refresh", "jti_refresh", "created_at", "updated_at", "enc_key"}).
			AddRow("client-1", "api", "hashed-pass", "hashed-key", access, int64(123456), int64(123457), "jti-1", createdAt, updatedAt, encKey)
		mock.ExpectQuery(readQuery).
			WithArgs("client-1", "api").
			WillReturnRows(rows)

		client, err := repo.ReadClient("api", "client-1")
		assert.NoError(t, err)
		assert.NotNil(t, client)
		assert.Equal(t, "client-1", client.ClientID)
		assert.Equal(t, "api", client.Realm)
		assert.Equal(t, map[string]any{"key": "value"}, *client.AccessData)
		assert.Equal(t, createdAt, *client.CreatedAt)
		assert.Equal(t, updatedAt, *client.UpdatedAt)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Client not found", func(t *testing.T) {
		mock.ExpectQuery(readQuery).
			WithArgs("client-1", "api").
			WillReturnError(sql.ErrNoRows)

		client, err := repo.ReadClient("api", "client-1")
		assert.Error(t, err)
		assert.Nil(t, client)
		assert.Equal(t, sql.ErrNoRows, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Invalid access JSON", func(t *testing.T) {
		_, encKey := encryptedAccessFixture(t, "api", "client-1", `{"key":"value"}`)
		rows := sqlmock.NewRows([]string{"client_id", "realm", "password", "api_key", "access", "enc_key"}).
			AddRow("client-1", "api", "hashed-pass", "hashed-key", "v1.invalid", encKey)
		mock.ExpectQuery(readQuery).
			WithArgs("client-1", "api").
			WillReturnRows(rows)

		client, err := repo.ReadClient("api", "client-1")
		assert.Error(t, err)
		assert.Nil(t, client)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestCreateClient(t *testing.T) {
	const createQuery = "INSERT INTO [\\w_]*.clients \\(client_id, realm, api_key, password, access, is_active, pwd_expiry, enc_key\\) VALUES \\(\\?,\\?,\\?,\\?,\\?,\\?,\\?,\\?\\)"
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close()
	sqlxDB := sqlx.NewDb(db, "mysql")
	repo := &Repo{db: sqlxDB, dbName: "testdb", masterKey: repoTestMasterKey}

	t.Run("Successful create", func(t *testing.T) {
		accessData := map[string]any{"key": "value"}
		expiry := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
		client := Client{
			ClientID:   "client-1",
			Realm:      "api",
			Password:   PtrFacade("pass"),
			APIKey:     PtrFacade("key"),
			AccessData: PtrFacade(any(accessData)),
			PwdExpiry:  &expiry,
		}
		mock.ExpectExec(createQuery).
			WithArgs(client.ClientID, client.Realm, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), true, expiry, sqlmock.AnyArg()).
			WillReturnResult(sqlmock.NewResult(1, 1))

		err := repo.CreateClient(client, "api")
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Invalid access JSON", func(t *testing.T) {
		invalidConfig := NonJSONSerializable{Data: func() {}}
		client := Client{
			ClientID:   "client-1",
			Realm:      "api",
			Password:   PtrFacade("pass"),
			APIKey:     PtrFacade("key"),
			AccessData: PtrFacade(any(invalidConfig)),
		}
		err := repo.CreateClient(client, "api")
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Database error", func(t *testing.T) {
		accessData := map[string]any{"key": "value"}
		client := Client{
			ClientID:   "client-1",
			Realm:      "api",
			Password:   PtrFacade("pass"),
			APIKey:     PtrFacade("key"),
			AccessData: PtrFacade(any(accessData)),
		}
		mock.ExpectExec(createQuery).
			WillReturnError(errors.New("db error"))

		err := repo.CreateClient(client, "api")
		assert.Error(t, err)
		assert.Equal(t, "db error", err.Error())
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestUpdateClient(t *testing.T) {
	const updateQuery = "UPDATE [\\w_]*.clients SET access = \\?, updated_at = UTC_TIMESTAMP\\(\\) WHERE client_id = \\? AND realm = \\?"
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close()
	sqlxDB := sqlx.NewDb(db, "mysql")
	repo := &Repo{db: sqlxDB, masterKey: repoTestMasterKey}

	t.Run("Successful update", func(t *testing.T) {
		_, wrappedKey := encryptedAccessFixture(t, "api", "client-1", `{"key":"old"}`)
		props := map[string]any{
			"access": `{"key":"updated"}`,
		}
		mock.ExpectQuery("SELECT enc_key FROM [\\w_]*.clients WHERE client_id = \\? AND realm = \\?").
			WithArgs("client-1", "api").
			WillReturnRows(sqlmock.NewRows([]string{"enc_key"}).AddRow(wrappedKey))
		mock.ExpectExec(updateQuery).
			WithArgs(sqlmock.AnyArg(), "client-1", "api").
			WillReturnResult(sqlmock.NewResult(1, 1))

		rowsAffected, err := repo.UpdateClient("client-1", "api", props)
		assert.NoError(t, err)
		assert.Equal(t, int64(1), rowsAffected)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Missing client while reading encryption key", func(t *testing.T) {
		props := map[string]any{"access": `{"key":"updated"}`}
		mock.ExpectQuery("SELECT enc_key FROM [\\w_]*.clients WHERE client_id = \\? AND realm = \\?").
			WithArgs("client-1", "api").
			WillReturnError(sql.ErrNoRows)

		rowsAffected, err := repo.UpdateClient("client-1", "api", props)
		assert.NoError(t, err)
		assert.Equal(t, int64(0), rowsAffected)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("No rows affected", func(t *testing.T) {
		_, wrappedKey := encryptedAccessFixture(t, "api", "client-1", `{"key":"old"}`)
		props := map[string]any{
			"access": `{"key":"updated"}`,
		}
		mock.ExpectQuery("SELECT enc_key FROM [\\w_]*.clients WHERE client_id = \\? AND realm = \\?").
			WithArgs("client-1", "api").
			WillReturnRows(sqlmock.NewRows([]string{"enc_key"}).AddRow(wrappedKey))
		mock.ExpectExec(updateQuery).
			WithArgs(sqlmock.AnyArg(), "client-1", "api").
			WillReturnResult(sqlmock.NewResult(0, 0))

		rowsAffected, err := repo.UpdateClient("client-1", "api", props)
		assert.NoError(t, err)
		assert.Equal(t, int64(0), rowsAffected)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Database error", func(t *testing.T) {
		_, wrappedKey := encryptedAccessFixture(t, "api", "client-1", `{"key":"old"}`)
		props := map[string]any{
			"access": `{"key":"updated"}`,
		}
		mock.ExpectQuery("SELECT enc_key FROM [\\w_]*.clients WHERE client_id = \\? AND realm = \\?").
			WithArgs("client-1", "api").
			WillReturnRows(sqlmock.NewRows([]string{"enc_key"}).AddRow(wrappedKey))
		mock.ExpectExec(updateQuery).
			WithArgs(sqlmock.AnyArg(), "client-1", "api").
			WillReturnError(errors.New("db error"))

		rowsAffected, err := repo.UpdateClient("client-1", "api", props)
		assert.Error(t, err)
		assert.Equal(t, "db error", err.Error())
		assert.Equal(t, int64(0), rowsAffected)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestUpdateClientInvalidatesAPIKeyCache(t *testing.T) {
	apiKeyCache.Clear()
	t.Cleanup(apiKeyCache.Clear)
	for _, entry := range []struct {
		clientID string
		realm    string
		key      string
	}{
		{clientID: "client-1", realm: "api", key: "first-key"},
		{clientID: "client-1", realm: "api", key: "second-key"},
		{clientID: "client-1", realm: "internal", key: "internal-key"},
		{clientID: "client-2", realm: "api", key: "other-client-key"},
	} {
		apiKeyCache.Set(apiKeyCacheKey(entry.realm, entry.key), StrTTLVal{
			ClientID: entry.clientID,
			Realm:    entry.realm,
			Expiry:   time.Now().Add(time.Hour).Unix(),
		})
	}

	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close()
	repo := &Repo{db: sqlx.NewDb(db, "mysql"), dbName: "testdb"}
	mock.ExpectExec("UPDATE [\\w_]*\\.clients SET is_active = \\?, updated_at = UTC_TIMESTAMP\\(\\) WHERE client_id = \\? AND realm = \\?").
		WithArgs(false, "client-1", "api").
		WillReturnResult(sqlmock.NewResult(0, 1))

	rowsAffected, err := repo.UpdateClient("client-1", "api", map[string]any{"is_active": false})
	assert.NoError(t, err)
	assert.Equal(t, int64(1), rowsAffected)
	for _, key := range []string{
		apiKeyCacheKey("api", "first-key"),
		apiKeyCacheKey("api", "second-key"),
	} {
		_, found := apiKeyCache.Get(key)
		assert.False(t, found, "updated client keys must be evicted")
	}
	for _, key := range []string{
		apiKeyCacheKey("internal", "internal-key"),
		apiKeyCacheKey("api", "other-client-key"),
	} {
		_, found := apiKeyCache.Get(key)
		assert.True(t, found, "unrelated client keys must remain cached")
	}
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestDeleteClient(t *testing.T) {
	const deleteQuery = "DELETE FROM [\\w_]*.clients WHERE client_id = \\? AND realm = \\?"
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close()
	sqlxDB := sqlx.NewDb(db, "mysql")
	repo := &Repo{db: sqlxDB, masterKey: repoTestMasterKey}

	t.Run("Successful delete with realm", func(t *testing.T) {
		mock.ExpectExec(deleteQuery).
			WithArgs("client-1", "api").
			WillReturnResult(sqlmock.NewResult(1, 1))

		rowsAffected, err := repo.DeleteClient("client-1", "api")
		assert.NoError(t, err)
		assert.Equal(t, int64(1), rowsAffected)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Successful delete without realm", func(t *testing.T) {
		mock.ExpectExec("DELETE FROM [\\w_]*.clients WHERE client_id = \\?").
			WithArgs("client-1").
			WillReturnResult(sqlmock.NewResult(2, 2))

		rowsAffected, err := repo.DeleteClient("client-1", "")
		assert.NoError(t, err)
		assert.Equal(t, int64(2), rowsAffected)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("No rows affected", func(t *testing.T) {
		mock.ExpectExec(deleteQuery).
			WithArgs("client-1", "api").
			WillReturnResult(sqlmock.NewResult(0, 0))

		rowsAffected, err := repo.DeleteClient("client-1", "api")
		assert.NoError(t, err)
		assert.Equal(t, int64(0), rowsAffected)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Database error", func(t *testing.T) {
		mock.ExpectExec(deleteQuery).
			WithArgs("client-1", "api").
			WillReturnError(errors.New("db error"))

		rowsAffected, err := repo.DeleteClient("client-1", "api")
		assert.Error(t, err)
		assert.Equal(t, "db error", err.Error())
		assert.Equal(t, int64(0), rowsAffected)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestDeleteClientInvalidatesAPIKeyCache(t *testing.T) {
	for _, test := range []struct {
		name  string
		realm string
	}{
		{name: "scoped deletion", realm: "api"},
		{name: "unscoped deletion"},
	} {
		t.Run(test.name, func(t *testing.T) {
			apiKeyCache.Clear()
			t.Cleanup(apiKeyCache.Clear)
			for _, entry := range []struct {
				clientID string
				realm    string
				key      string
			}{
				{clientID: "client-1", realm: "api", key: "api-key"},
				{clientID: "client-1", realm: "internal", key: "internal-key"},
				{clientID: "client-2", realm: "api", key: "other-client-key"},
			} {
				apiKeyCache.Set(apiKeyCacheKey(entry.realm, entry.key), StrTTLVal{
					ClientID: entry.clientID,
					Realm:    entry.realm,
					Expiry:   time.Now().Add(time.Hour).Unix(),
				})
			}

			db, mock, err := sqlmock.New()
			assert.NoError(t, err)
			defer db.Close()
			repo := &Repo{db: sqlx.NewDb(db, "mysql"), dbName: "testdb"}
			query := "DELETE FROM [\\w_]*\\.clients WHERE client_id = \\?"
			if test.realm != "" {
				query += " AND realm = \\?"
			}
			expectation := mock.ExpectExec(query)
			if test.realm != "" {
				expectation = expectation.WithArgs("client-1", test.realm)
			} else {
				expectation = expectation.WithArgs("client-1")
			}
			expectation.WillReturnResult(sqlmock.NewResult(0, 1))

			rowsAffected, err := repo.DeleteClient("client-1", test.realm)
			assert.NoError(t, err)
			assert.Equal(t, int64(1), rowsAffected)
			_, apiKeyFound := apiKeyCache.Get(apiKeyCacheKey("api", "api-key"))
			assert.False(t, apiKeyFound)
			_, internalKeyFound := apiKeyCache.Get(apiKeyCacheKey("internal", "internal-key"))
			assert.Equal(t, test.realm != "", internalKeyFound, "only unscoped deletion removes other realm entries")
			_, otherClientFound := apiKeyCache.Get(apiKeyCacheKey("api", "other-client-key"))
			assert.True(t, otherClientFound)
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestLoginClient(t *testing.T) {
	const lookupQuery = "SELECT \\* FROM [\\w_]*.clients WHERE client_id = \\? AND realm = \\? AND is_active = true"
	const updateQuery = "UPDATE [\\w_]*.clients SET last_login = \\?, last_refresh = \\?, jti_refresh = \\? WHERE client_id = \\? AND realm = \\?"
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close()
	sqlxDB := sqlx.NewDb(db, "mysql")
	repo := &Repo{db: sqlxDB, masterKey: repoTestMasterKey}
	config := setupConfig()

	pwd := "verySecret"
	hashedPwd := auth.HashPassword(&pwd)
	login := &Client{
		ClientID: "client-1",
		Realm:    "api",
		Password: &pwd,
	}

	t.Run("Successful login", func(t *testing.T) {
		access, encKey := encryptedAccessFixture(t, "api", "client-1", `{"key":"value"}`)
		rows := sqlmock.NewRows([]string{"client_id", "realm", "password", "api_key", "access", "last_login", "last_refresh", "jti_refresh", "created_at", "updated_at", "is_active", "enc_key"}).
			AddRow("client-1", "api", *hashedPwd, "key", access, nil, nil, "jti-1", nil, nil, true, encKey)
		mock.ExpectQuery(lookupQuery).
			WithArgs("client-1", "api").
			WillReturnRows(rows)
		mock.ExpectExec(updateQuery).
			WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), "client-1", "api").
			WillReturnResult(sqlmock.NewResult(1, 1))

		tokenPair, err := repo.LoginClient(login, config)
		assert.NoError(t, err)
		assert.NotNil(t, tokenPair)
		tokenClaims, err := auth.VerifyToken(tokenPair.AccessToken, config.Realms["api"].VerificationPublicKey, nil)
		assert.NoError(t, err)
		assert.Equal(t, map[string]any{"key": "value"}, tokenClaims["access"])
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Inactive client login denied", func(t *testing.T) {
		rows := sqlmock.NewRows([]string{"client_id", "realm", "password", "api_key", "access", "last_login", "last_refresh", "jti_refresh", "created_at", "updated_at", "is_active"}).
			AddRow("client-1", "api", *hashedPwd, "key", `{"key":"value"}`, nil, nil, "jti-1", nil, nil, false)
		mock.ExpectQuery(lookupQuery).
			WithArgs("client-1", "api").
			WillReturnRows(rows)

		tokenPair, err := repo.LoginClient(login, config)
		assert.Error(t, err)
		assert.Nil(t, tokenPair)
		assert.Equal(t, "access denied", err.Error())
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Client not found", func(t *testing.T) {
		mock.ExpectQuery(lookupQuery).
			WithArgs("client-1", "api").
			WillReturnError(sql.ErrNoRows)

		tokenPair, err := repo.LoginClient(login, config)
		assert.Error(t, err)
		assert.Nil(t, tokenPair)
		assert.Equal(t, "access denied", err.Error())
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Invalid password", func(t *testing.T) {
		wrongPass := "wrong-pass"
		login := &Client{
			ClientID: "client-1",
			Realm:    "api",
			Password: &wrongPass,
		}
		rows := sqlmock.NewRows([]string{"client_id", "realm", "password", "api_key", "access", "last_login", "last_refresh", "jti_refresh", "created_at", "updated_at"}).
			AddRow("client-1", "api", *hashedPwd, "key", `{"key":"value"}`, nil, nil, "jti-1", nil, nil)
		mock.ExpectQuery(lookupQuery).
			WithArgs("client-1", "api").
			WillReturnRows(rows)

		tokenPair, err := repo.LoginClient(login, config)
		assert.Error(t, err)
		assert.Nil(t, tokenPair)
		assert.Equal(t, "access denied", err.Error())
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Expired password", func(t *testing.T) {
		expiry := time.Now().Add(-time.Minute)
		rows := sqlmock.NewRows([]string{"client_id", "realm", "password", "pwd_expiry", "is_active"}).
			AddRow("client-1", "api", *hashedPwd, expiry, true)
		mock.ExpectQuery(lookupQuery).
			WithArgs("client-1", "api").
			WillReturnRows(rows)

		tokenPair, err := repo.LoginClient(login, config)
		assert.Nil(t, tokenPair)
		assert.ErrorIs(t, err, errPasswordExpired)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestVerifyAPIKey(t *testing.T) {
	const lookupQuery = "SELECT client_id, access, enc_key, is_active FROM [\\w_]*.clients WHERE api_key = \\?"
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close()
	sqlxDB := sqlx.NewDb(db, "mysql")
	repo := &Repo{db: sqlxDB, masterKey: repoTestMasterKey}
	config := setupConfig()

	t.Run("Successful verify from cache", func(t *testing.T) {
		apiKey := "key"
		access := any(map[string]any{"key": "cached"})
		apiKeyCache.Set(apiKeyCacheKey("api", apiKey), StrTTLVal{
			ClientID:   "client-1",
			AccessData: &access,
			Expiry:     time.Now().Unix() + 600,
		})

		claims, err := repo.VerifyAPIKey(apiKey, "api", config)
		assert.NoError(t, err)
		assert.NotNil(t, claims)
		assert.Equal(t, "client-1", claims["client_id"])
		assert.Equal(t, map[string]any{"key": "cached"}, claims["access"])
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Successful verify from DB", func(t *testing.T) {
		apiKey := "anotherKey"
		hashedAPIKey := auth.HashAPIKey(&apiKey, "api")
		access, encKey := encryptedAccessFixture(t, "api", "client-1", `{"key":"value"}`)
		rows := sqlmock.NewRows([]string{"client_id", "access", "enc_key", "is_active"}).
			AddRow("client-1", access, encKey, true)
		mock.ExpectQuery(lookupQuery).
			WithArgs(*hashedAPIKey).
			WillReturnRows(rows)

		claims, err := repo.VerifyAPIKey(apiKey, "api", config)
		assert.NoError(t, err)
		assert.NotNil(t, claims)
		assert.Equal(t, "client-1", claims["client_id"])
		assert.Equal(t, map[string]any{"key": "value"}, claims["access"])
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Invalid API key", func(t *testing.T) {
		apiKey := "invalidKey"
		hashedAPIKey := auth.HashAPIKey(&apiKey, "api")
		mock.ExpectQuery(lookupQuery).
			WithArgs(*hashedAPIKey).
			WillReturnError(sql.ErrNoRows)

		claims, err := repo.VerifyAPIKey(apiKey, "api", config)
		assert.Error(t, err)
		assert.Nil(t, claims)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Cache size limit enforced", func(t *testing.T) {
		apiKeyCache.Clear()

		for i := 0; i < apiKeyCacheMaxSize+10; i++ {
			cacheKey := fmt.Sprintf("api:key%d", i)
			apiKeyCache.Set(cacheKey, StrTTLVal{
				ClientID:   fmt.Sprintf("client-%d", i),
				AccessData: nil,
				Expiry:     time.Now().Unix() + 600,
			})
			if i >= apiKeyCacheMaxSize-1 {
				ensureAPICacheCapacity()
			}
		}

		finalSize := apiKeyCache.Len()
		assert.LessOrEqual(t, finalSize, apiKeyCacheMaxSize, "cache size should not exceed limit")
	})

	t.Run("Expired entries removed on capacity", func(t *testing.T) {
		apiKeyCache.Clear()
		now := time.Now().Unix()

		apiKeyCache.Set("api:old-key", StrTTLVal{
			ClientID:   "client-old",
			AccessData: nil,
			Expiry:     now - 100,
		})

		for i := 0; i < apiKeyCacheMaxSize; i++ {
			cacheKey := fmt.Sprintf("api:key%d", i)
			apiKeyCache.Set(cacheKey, StrTTLVal{
				ClientID:   fmt.Sprintf("client-%d", i),
				AccessData: nil,
				Expiry:     now + 600,
			})
			if i >= apiKeyCacheMaxSize-1 {
				ensureAPICacheCapacity()
			}
		}

		_, found := apiKeyCache.Get("api:old-key")
		assert.False(t, found, "expired entry should be removed when capacity reached")
		assert.LessOrEqual(t, apiKeyCache.Len(), apiKeyCacheMaxSize, "cache size should not exceed limit")
	})
}

func TestRefreshToken(t *testing.T) {
	const lookupQuery = "SELECT \\* from [\\w_]*.clients WHERE client_id = \\? AND realm = \\?"
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close()
	sqlxDB := sqlx.NewDb(db, "mysql")
	repo := &Repo{db: sqlxDB, masterKey: repoTestMasterKey}
	config := setupConfig()
	claims := jwt.MapClaims{
		"client_id": "client-1",
		"jti":       "refresh-jti-1",
		"sid":       "session1",
		"sex":       time.Now().Unix() + 3600,
	}

	t.Run("Successful refresh", func(t *testing.T) {
		pass := "pass"
		hashedPass := auth.HashPassword(&pass)
		access, encKey := encryptedAccessFixture(t, "api", "client-1", `{"key":"value"}`)
		rows := sqlmock.NewRows([]string{"client_id", "realm", "password", "api_key", "access", "last_login", "last_refresh", "jti_refresh", "created_at", "updated_at", "enc_key"}).
			AddRow("client-1", "api", *hashedPass, "key", access, nil, nil, "refresh-jti-1", nil, nil, encKey)
		mock.ExpectQuery(lookupQuery).
			WithArgs("client-1", "api").
			WillReturnRows(rows)
		mock.ExpectExec("UPDATE [\\w_]*.clients SET last_refresh = \\?, jti_refresh = \\? WHERE client_id = \\? AND realm = \\?").
			WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), "client-1", "api").
			WillReturnResult(sqlmock.NewResult(1, 1))

		tokenPair, err := repo.RefreshToken(claims, "api", config)
		assert.NoError(t, err)
		assert.NotNil(t, tokenPair)
		tokenClaims, err := auth.VerifyToken(tokenPair.AccessToken, config.Realms["api"].VerificationPublicKey, nil)
		assert.NoError(t, err)
		assert.Equal(t, map[string]any{"key": "value"}, tokenClaims["access"])
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Invalid client_id", func(t *testing.T) {
		invalidClaims := jwt.MapClaims{
			"client_id": 123, // Invalid type
		}
		tokenPair, err := repo.RefreshToken(invalidClaims, "api", config)
		assert.Error(t, err)
		assert.Nil(t, tokenPair)
		assert.Equal(t, "client_id claim is not valid", err.Error())
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Client not found", func(t *testing.T) {
		mock.ExpectQuery(lookupQuery).
			WithArgs("client-1", "api").
			WillReturnError(sql.ErrNoRows)

		tokenPair, err := repo.RefreshToken(claims, "api", config)
		assert.Error(t, err)
		assert.Nil(t, tokenPair)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestLogoutClient(t *testing.T) {
	const updateQuery = "UPDATE [\\w_]*.clients SET last_refresh = NULL, jti_refresh = NULL WHERE client_id = \\? AND realm = \\?"
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close()
	sqlxDB := sqlx.NewDb(db, "mysql")
	repo := &Repo{db: sqlxDB}
	claims := jwt.MapClaims{
		"client_id": "client-1",
	}

	t.Run("Successful logout", func(t *testing.T) {
		mock.ExpectExec(updateQuery).
			WithArgs("client-1", "api").
			WillReturnResult(sqlmock.NewResult(1, 1))

		err := repo.LogoutClient(claims, "api")
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Invalid client_id", func(t *testing.T) {
		invalidClaims := jwt.MapClaims{
			"client_id": 123, // Invalid type
		}
		err := repo.LogoutClient(invalidClaims, "api")
		assert.Error(t, err)
		assert.Equal(t, "client_id claim is not valid", err.Error())
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Client not found", func(t *testing.T) {
		mock.ExpectExec(updateQuery).
			WithArgs("client-1", "api").
			WillReturnResult(sqlmock.NewResult(0, 0))

		err := repo.LogoutClient(claims, "api")
		assert.Error(t, err)
		assert.Equal(t, "client id not found", err.Error())
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}
