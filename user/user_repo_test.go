package user

import (
	"bytes"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"junglerider/gatekeeper/auth"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jmoiron/sqlx"
	"github.com/xlzd/gotp"
)

var repoTestMasterKey = bytes.Repeat([]byte{0x42}, 32)

func testSigningKeys(seedByte byte) (string, string) {
	seed := bytes.Repeat([]byte{seedByte}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	return base64.StdEncoding.EncodeToString(seed),
		base64.StdEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey))
}

func encryptedAccessFixture(t *testing.T, realm, clientID, name, access string) (string, string) {
	t.Helper()
	owner := auth.OwnerContext("user", realm, clientID, name)
	dataKey, wrappedKey, err := auth.GenerateWrappedDataKey(repoTestMasterKey, owner)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := auth.EncryptAccess(access, dataKey, owner)
	clear(dataKey)
	if err != nil {
		t.Fatal(err)
	}
	return encrypted, wrappedKey
}

func setupTestDB(t *testing.T) (*sqlx.DB, sqlmock.Sqlmock) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	sqlxDB := sqlx.NewDb(db, "sqlmock")
	return sqlxDB, mock
}

func TestListUsers(t *testing.T) {
	db, mock := setupTestDB(t)
	defer db.Close()
	repo := &Repo{db: db, masterKey: repoTestMasterKey}
	const query = "SELECT client_id, name FROM [\\w_]*.users WHERE realm = \\? ORDER BY client_id, name"

	t.Run("Success", func(t *testing.T) {
		realm := "test"
		clientID := PtrFacade("client1")
		isActive := PtrFacade(true)
		const query = "SELECT client_id, name FROM [\\w_]*.users WHERE realm = \\? AND is_active = \\? AND client_id = \\? ORDER BY client_id, name"
		rows := sqlmock.NewRows([]string{"client_id", "name"}).
			AddRow("client1", "user1").
			AddRow("client1", "user2")
		mock.ExpectQuery(query).
			WithArgs(realm, *isActive, *clientID).
			WillReturnRows(rows)

		users, err := repo.ListUsers(realm, clientID, isActive, nil)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(users) != 2 {
			t.Errorf("expected 2 users, got %d", len(users))
		}
		if users[0].ClientID != "client1" || users[0].Name != "user1" {
			t.Errorf("expected client1/user1, got %s/%s", users[0].ClientID, users[0].Name)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("NoFilters", func(t *testing.T) {
		realm := "test"
		rows := sqlmock.NewRows([]string{"client_id", "name"}).
			AddRow("client1", "user1")
		mock.ExpectQuery(query).
			WithArgs(realm).
			WillReturnRows(rows)

		users, err := repo.ListUsers(realm, nil, nil, nil)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(users) != 1 {
			t.Errorf("expected 1 user, got %d", len(users))
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("ExpiryFilter", func(t *testing.T) {
		expiry := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
		rows := sqlmock.NewRows([]string{"client_id", "name"}).AddRow("client1", "user1")
		mock.ExpectQuery("SELECT client_id, name FROM [\\w_]*.users WHERE realm = \\? AND pwd_expiry <= \\? ORDER BY client_id, name").
			WithArgs("test", expiry).
			WillReturnRows(rows)

		users, err := repo.ListUsers("test", nil, nil, &expiry)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(users) != 1 || users[0].Name != "user1" {
			t.Errorf("expected matching user, got %v", users)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("QueryError", func(t *testing.T) {
		realm := "test"
		mock.ExpectQuery(query).
			WithArgs(realm).
			WillReturnError(errors.New("db error"))

		users, err := repo.ListUsers(realm, nil, nil, nil)
		if err == nil || err.Error() != "db error" {
			t.Errorf("expected db error, got %v", err)
		}
		if users != nil {
			t.Errorf("expected nil users, got %v", users)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("ScanError", func(t *testing.T) {
		realm := "test"
		rows := sqlmock.NewRows([]string{"client_id", "name"}).
			AddRow(nil, "user1") // Invalid data to cause scan error
		mock.ExpectQuery(query).
			WithArgs(realm).
			WillReturnRows(rows)

		users, err := repo.ListUsers(realm, nil, nil, nil)
		if err == nil {
			t.Error("expected scan error, got nil")
		}
		if users != nil {
			t.Errorf("expected nil users, got %v", users)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})
}

// TestListUsers_PostgresRebindsPlaceholdersAndUsesCurrentSchema checks PostgreSQL query formatting.
func TestListUsers_PostgresRebindsPlaceholdersAndUsesCurrentSchema(t *testing.T) {
	db, mock := setupTestDB(t)
	defer db.Close()
	repo := &Repo{db: sqlx.NewDb(db.DB, "pgx"), dbName: "testdb", masterKey: repoTestMasterKey}
	mock.ExpectQuery("^SELECT client_id, name FROM users WHERE realm = \\$1 ORDER BY client_id, name$").
		WithArgs("api").
		WillReturnRows(sqlmock.NewRows([]string{"client_id", "name"}))

	users, err := repo.ListUsers("api", nil, nil, nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(users) != 0 {
		t.Fatalf("expected no users, got %v", users)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unfulfilled expectations: %v", err)
	}
}

func TestReadUser(t *testing.T) {
	const query = "SELECT \\* FROM [\\w_]*.users WHERE client_id =\\? AND realm =\\? AND name =\\?"
	db, mock := setupTestDB(t)
	defer db.Close()
	repo := &Repo{db: db, masterKey: repoTestMasterKey}

	t.Run("Success", func(t *testing.T) {
		u := &UserPK{Realm: "test", ClientID: "client1", Name: "user1"}
		access, encKey := encryptedAccessFixture(t, u.Realm, u.ClientID, u.Name, `{"key":"value"}`)
		createdAt := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
		updatedAt := time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC)
		rows := sqlmock.NewRows([]string{"client_id", "realm", "name", "password", "access", "is_active", "last_login", "last_refresh", "created_at", "updated_at", "otp_enabled", "otp_secret", "enc_key"}).
			AddRow("client1", "test", "user1", "hashed", access, true, 1234567890, 1234567890, createdAt, updatedAt, true, "secret", encKey)
		mock.ExpectQuery(query).
			WithArgs(u.ClientID, u.Realm, u.Name).
			WillReturnRows(rows)

		user, err := repo.ReadUser(u)
		fmt.Printf("Read user: %+v, %v\n", user, err)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if user == nil || user.ClientID != "client1" || user.Realm != "test" || user.Name != "user1" {
			t.Errorf("expected valid user, got %v", user)
		}
		if user.AccessData == nil {
			t.Errorf("expected non-nil AccessData, got %v", user.AccessData)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("NotFound", func(t *testing.T) {
		u := &UserPK{Realm: "test", ClientID: "client1", Name: "user1"}
		mock.ExpectQuery(query).
			WithArgs(u.ClientID, u.Realm, u.Name).
			WillReturnError(sql.ErrNoRows)

		user, err := repo.ReadUser(u)
		if err != sql.ErrNoRows {
			t.Errorf("expected sql.ErrNoRows, got %v", err)
		}
		if user != nil {
			t.Errorf("expected nil user, got %v", user)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("QueryError", func(t *testing.T) {
		u := &UserPK{Realm: "test", ClientID: "client1", Name: "user1"}
		mock.ExpectQuery(query).
			WithArgs(u.ClientID, u.Realm, u.Name).
			WillReturnError(errors.New("db error"))

		user, err := repo.ReadUser(u)
		if err == nil || err.Error() != "db error" {
			t.Errorf("expected db error, got %v", err)
		}
		if user != nil {
			t.Errorf("expected nil user, got %v", user)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})
}

func TestCreateUser(t *testing.T) {
	const query = "INSERT INTO [\\w_]*.users \\(client_id, realm, name, password, access, is_active, pwd_expiry, otp_enabled, otp_secret, enc_key\\) VALUES \\(\\?,\\?,\\?,\\?,\\?,\\?,\\?,\\?,\\?,\\?\\)"

	db, mock := setupTestDB(t)
	defer db.Close()
	repo := &Repo{db: db, dbName: "testdb", masterKey: repoTestMasterKey}

	t.Run("Success", func(t *testing.T) {
		expiry := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
		user := User{
			ClientID:   "client1",
			Realm:      "test",
			Name:       "user1",
			Password:   PtrFacade("password123"),
			Access:     PtrFacade(`{"key":"value"}`),
			IsActive:   PtrFacade(true),
			OTPEnabled: PtrFacade(false),
			OTPSecret:  PtrFacade("secret"),
			PwdExpiry:  &expiry,
		}
		mock.ExpectExec(query).
			WithArgs(user.ClientID, user.Realm, user.Name, sqlmock.AnyArg(), sqlmock.AnyArg(), *user.IsActive, expiry, *user.OTPEnabled, sqlmock.AnyArg(), sqlmock.AnyArg()).
			WillReturnResult(sqlmock.NewResult(1, 1))

		err := repo.CreateUser(user)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("NoOTPSecret", func(t *testing.T) {
		user := User{
			ClientID:   "client1",
			Realm:      "test",
			Name:       "user1",
			Password:   PtrFacade("password123"),
			Access:     PtrFacade(`{"key":"value"}`),
			IsActive:   PtrFacade(true),
			OTPEnabled: PtrFacade(false),
			OTPSecret:  nil,
		}
		mock.ExpectExec(query).
			WithArgs(user.ClientID, user.Realm, user.Name, sqlmock.AnyArg(), sqlmock.AnyArg(), *user.IsActive, nil, *user.OTPEnabled, nil, sqlmock.AnyArg()).
			WillReturnResult(sqlmock.NewResult(1, 1))

		err := repo.CreateUser(user)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("DuplicateError", func(t *testing.T) {
		user := User{
			ClientID:   "client1",
			Realm:      "test",
			Name:       "user1",
			Password:   PtrFacade("password123"),
			IsActive:   PtrFacade(true),
			OTPEnabled: PtrFacade(false),
		}
		mock.ExpectExec(query).
			WithArgs(user.ClientID, user.Realm, user.Name, sqlmock.AnyArg(), nil, *user.IsActive, nil, *user.OTPEnabled, nil, sqlmock.AnyArg()).
			WillReturnError(errors.New("Duplicate entry"))

		err := repo.CreateUser(user)
		if err == nil || !strings.Contains(err.Error(), "Duplicate") {
			t.Errorf("expected Duplicate entry error, got %v", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("ExecError", func(t *testing.T) {
		user := User{
			ClientID:   "client1",
			Realm:      "test",
			Name:       "user1",
			Password:   PtrFacade("password123"),
			IsActive:   PtrFacade(true),
			OTPEnabled: PtrFacade(false),
		}
		mock.ExpectExec(query).
			WithArgs(user.ClientID, user.Realm, user.Name, sqlmock.AnyArg(), nil, *user.IsActive, nil, *user.OTPEnabled, nil, sqlmock.AnyArg()).
			WillReturnError(errors.New("db error"))

		err := repo.CreateUser(user)
		if err == nil || err.Error() != "db error" {
			t.Errorf("expected db error, got %v", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})
}

func TestUpdateUser(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		db, mock := setupTestDB(t)
		defer db.Close()
		repo := &Repo{db: db, masterKey: repoTestMasterKey}

		u := &UserPK{Realm: "test", ClientID: "client1", Name: "user1"}
		props := map[string]any{"access": `{"key":"value"}`, "is_active": true}
		query := "UPDATE [\\w_]*\\.users SET access = \\?, is_active = \\?, updated_at = UTC_TIMESTAMP\\(\\) WHERE client_id = \\? AND realm = \\? AND name = \\?"
		_, wrappedKey, err := auth.GenerateWrappedDataKey(repoTestMasterKey, auth.OwnerContext("user", u.Realm, u.ClientID, u.Name))
		if err != nil {
			t.Fatal(err)
		}
		mock.ExpectQuery("SELECT enc_key, access, otp_secret FROM [\\w_]*\\.users WHERE client_id = \\? AND realm = \\? AND name = \\?").
			WithArgs(u.ClientID, u.Realm, u.Name).
			WillReturnRows(sqlmock.NewRows([]string{"enc_key", "access", "otp_secret"}).AddRow(wrappedKey, nil, nil))
		mock.ExpectExec(query).
			WithArgs(sqlmock.AnyArg(), true, u.ClientID, u.Realm, u.Name).
			WillReturnResult(sqlmock.NewResult(0, 1))

		rowsAffected, err := repo.UpdateUser(u, props)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if rowsAffected != 1 {
			t.Errorf("expected 1 row affected, got %d", rowsAffected)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("Missing user while preparing encrypted updates", func(t *testing.T) {
		db, mock := setupTestDB(t)
		defer db.Close()
		repo := &Repo{db: db, masterKey: repoTestMasterKey}
		u := &UserPK{Realm: "test", ClientID: "client1", Name: "user1"}
		mock.ExpectQuery("SELECT enc_key, access, otp_secret FROM [\\w_]*\\.users WHERE client_id = \\? AND realm = \\? AND name = \\?").
			WithArgs(u.ClientID, u.Realm, u.Name).
			WillReturnError(sql.ErrNoRows)

		rowsAffected, err := repo.UpdateUser(u, map[string]any{"access": `{"key":"value"}`})
		if err != nil {
			t.Fatalf("expected missing user to return zero affected rows, got %v", err)
		}
		if rowsAffected != 0 {
			t.Fatalf("expected zero affected rows, got %d", rowsAffected)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("NoRowsAffected", func(t *testing.T) {
		db, mock := setupTestDB(t)
		defer db.Close()
		repo := &Repo{db: db}

		u := &UserPK{Realm: "test", ClientID: "client1", Name: "user1"}
		props := map[string]any{"is_active": true}
		query := "UPDATE [\\w_]*\\.users SET is_active = \\?, updated_at = UTC_TIMESTAMP\\(\\) WHERE client_id = \\? AND realm = \\? AND name = \\?"
		mock.ExpectExec(query).
			WithArgs(true, u.ClientID, u.Realm, u.Name).
			WillReturnResult(sqlmock.NewResult(0, 0))

		rowsAffected, err := repo.UpdateUser(u, props)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if rowsAffected != 0 {
			t.Errorf("expected 0 rows affected, got %d", rowsAffected)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("ExecError", func(t *testing.T) {
		db, mock := setupTestDB(t)
		defer db.Close()
		repo := &Repo{db: db}

		u := &UserPK{Realm: "test", ClientID: "client1", Name: "user1"}
		props := map[string]any{"is_active": true}
		query := "UPDATE [\\w_]*\\.users SET is_active = \\?, updated_at = UTC_TIMESTAMP\\(\\) WHERE client_id = \\? AND realm = \\? AND name = \\?"
		mock.ExpectExec(query).
			WithArgs(true, u.ClientID, u.Realm, u.Name).
			WillReturnError(errors.New("db error"))

		rowsAffected, err := repo.UpdateUser(u, props)
		if err == nil || err.Error() != "db error" {
			t.Errorf("expected db error, got %v", err)
		}
		if rowsAffected != 0 {
			t.Errorf("expected 0 rows affected, got %d", rowsAffected)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("NullProp", func(t *testing.T) {
		db, mock := setupTestDB(t)
		defer db.Close()
		repo := &Repo{db: db}

		u := &UserPK{Realm: "test", ClientID: "client1", Name: "user1"}
		props := map[string]any{"access": nil}
		query := "UPDATE [\\w_]*\\.users SET access = NULL, updated_at = UTC_TIMESTAMP\\(\\) WHERE client_id = \\? AND realm = \\? AND name = \\?"
		mock.ExpectExec(query).
			WithArgs(u.ClientID, u.Realm, u.Name).
			WillReturnResult(sqlmock.NewResult(0, 1))

		rowsAffected, err := repo.UpdateUser(u, props)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if rowsAffected != 1 {
			t.Errorf("expected 1 row affected, got %d", rowsAffected)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("ClearOTPSecret", func(t *testing.T) {
		db, mock := setupTestDB(t)
		defer db.Close()
		repo := &Repo{db: db}

		u := &UserPK{Realm: "test", ClientID: "client1", Name: "user1"}
		props := map[string]any{"otp_secret": nil}
		query := "UPDATE [\\w_]*\\.users SET otp_secret = NULL, updated_at = UTC_TIMESTAMP\\(\\) WHERE client_id = \\? AND realm = \\? AND name = \\?"
		mock.ExpectExec(query).
			WithArgs(u.ClientID, u.Realm, u.Name).
			WillReturnResult(sqlmock.NewResult(0, 1))

		rowsAffected, err := repo.UpdateUser(u, props)
		if err != nil {
			t.Fatalf("expected OTP clear to succeed, got %v", err)
		}
		if rowsAffected != 1 {
			t.Fatalf("expected one updated row, got %d", rowsAffected)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("unfulfilled expectations: %v", err)
		}
	})
}

func TestUpdateUser_EncryptsOTPSecret(t *testing.T) {
	db, mock := setupTestDB(t)
	defer db.Close()
	repo := &Repo{db: db, dbName: "testdb", masterKey: repoTestMasterKey}
	u := &UserPK{Realm: "test", ClientID: "client1", Name: "user1"}
	owner := auth.OwnerContext("user", u.Realm, u.ClientID, u.Name)
	_, wrappedKey, err := auth.GenerateWrappedDataKey(repoTestMasterKey, owner)
	if err != nil {
		t.Fatal(err)
	}

	mock.ExpectQuery("SELECT enc_key, access, otp_secret FROM testdb\\.users WHERE client_id = \\? AND realm = \\? AND name = \\?").
		WithArgs(u.ClientID, u.Realm, u.Name).
		WillReturnRows(sqlmock.NewRows([]string{"enc_key", "access", "otp_secret"}).AddRow(wrappedKey, nil, nil))
	mock.ExpectExec("UPDATE testdb\\.users SET otp_secret = \\?, updated_at = UTC_TIMESTAMP\\(\\) WHERE client_id = \\? AND realm = \\? AND name = \\?").
		WithArgs(sqlmock.AnyArg(), u.ClientID, u.Realm, u.Name).
		WillReturnResult(sqlmock.NewResult(0, 1))

	rowsAffected, err := repo.UpdateUser(u, map[string]any{"otp_secret": "JBSWY3DPEHPK3PXP"})
	if err != nil {
		t.Fatalf("expected re-enrollment update to succeed, got %v", err)
	}
	if rowsAffected != 1 {
		t.Fatalf("expected one updated row, got %d", rowsAffected)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unfulfilled expectations: %v", err)
	}
}

func TestUpdateUserRenameRebindsAccess(t *testing.T) {
	db, mock := setupTestDB(t)
	defer db.Close()
	repo := &Repo{db: db, dbName: "testdb", masterKey: repoTestMasterKey}
	u := &UserPK{Realm: "test", ClientID: "client1", Name: "user1"}
	oldOwner := auth.OwnerContext("user", u.Realm, u.ClientID, u.Name)
	newOwner := auth.OwnerContext("user", u.Realm, u.ClientID, "user2")
	accessJSON := `{"canRead":true}`
	dataKey, wrappedKey, err := auth.GenerateWrappedDataKey(repoTestMasterKey, oldOwner)
	if err != nil {
		t.Fatal(err)
	}
	encryptedAccess, err := auth.EncryptAccess(accessJSON, dataKey, oldOwner)
	clear(dataKey)
	if err != nil {
		t.Fatal(err)
	}

	mock.ExpectQuery("SELECT enc_key, access, otp_secret FROM testdb\\.users WHERE client_id = \\? AND realm = \\? AND name = \\?").
		WithArgs(u.ClientID, u.Realm, u.Name).
		WillReturnRows(sqlmock.NewRows([]string{"enc_key", "access", "otp_secret"}).AddRow(wrappedKey, encryptedAccess, nil))
	props := map[string]any{"name": "user2"}
	if err := repo.prepareUserUpdates(u, props); err != nil {
		t.Fatalf("expected rename to rebind access data, got %v", err)
	}

	newDataKey, err := auth.UnwrapDataKey(props["enc_key"].(string), repoTestMasterKey, newOwner)
	if err != nil {
		t.Fatalf("expected new wrapped key to be bound to new name, got %v", err)
	}
	defer clear(newDataKey)
	decrypted, err := auth.DecryptAccess(props["access"].(string), newDataKey, newOwner)
	if err != nil {
		t.Fatalf("expected access data to be bound to new name, got %v", err)
	}
	if decrypted != accessJSON {
		t.Fatalf("expected access data %s, got %s", accessJSON, decrypted)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unfulfilled expectations: %v", err)
	}
}

func TestDeleteUser(t *testing.T) {
	const query = "DELETE FROM [\\w_]*.users WHERE client_id = \\? AND realm = \\? AND name = \\?"
	db, mock := setupTestDB(t)
	defer db.Close()
	repo := &Repo{db: db}

	t.Run("Success", func(t *testing.T) {
		u := &UserPK{Realm: "test", ClientID: "client1", Name: "user1"}
		mock.ExpectExec(query).
			WithArgs(u.ClientID, u.Realm, u.Name).
			WillReturnResult(sqlmock.NewResult(0, 1))

		rowsAffected, err := repo.DeleteUser(u)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if rowsAffected != 1 {
			t.Errorf("expected 1 row affected, got %d", rowsAffected)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("NoRowsAffected", func(t *testing.T) {
		u := &UserPK{Realm: "test", ClientID: "client1", Name: "user1"}
		mock.ExpectExec(query).
			WithArgs(u.ClientID, u.Realm, u.Name).
			WillReturnResult(sqlmock.NewResult(0, 0))

		rowsAffected, err := repo.DeleteUser(u)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if rowsAffected != 0 {
			t.Errorf("expected 0 rows affected, got %d", rowsAffected)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("ExecError", func(t *testing.T) {
		u := &UserPK{Realm: "test", ClientID: "client1", Name: "user1"}
		mock.ExpectExec(query).
			WithArgs(u.ClientID, u.Realm, u.Name).
			WillReturnError(errors.New("db error"))

		rowsAffected, err := repo.DeleteUser(u)
		if err == nil || err.Error() != "db error" {
			t.Errorf("expected db error, got %v", err)
		}
		if rowsAffected != 0 {
			t.Errorf("expected 0 rows affected, got %d", rowsAffected)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})
}

func TestLoginUser(t *testing.T) {
	const lookupQuery = "SELECT \\* FROM [\\w_]*.users WHERE client_id = \\? AND realm = \\? AND name = \\? AND is_active = true"
	const updateQuery = "UPDATE [\\w_]*.users SET last_login = \\?, last_refresh = \\?, jti_refresh = \\? WHERE client_id = \\? AND realm = \\? AND name = \\?"
	db, mock := setupTestDB(t)
	defer db.Close()
	repo := &Repo{db: db, masterKey: repoTestMasterKey}
	config := setupTestConfig()

	t.Run("Success", func(t *testing.T) {
		login := &User{ClientID: "client1", Realm: "test", Name: "user1", Password: PtrFacade("password123")}
		hashedPassword := auth.HashPassword(login.Password)
		access, encKey := encryptedAccessFixture(t, login.Realm, login.ClientID, login.Name, `{"key":"value"}`)
		rows := sqlmock.NewRows([]string{"client_id", "realm", "name", "password", "access", "is_active", "jti_refresh", "enc_key"}).
			AddRow("client1", "test", "user1", *hashedPassword, access, true, "refresh-jti-1", encKey)
		mock.ExpectQuery(lookupQuery).
			WithArgs(login.ClientID, login.Realm, login.Name).
			WillReturnRows(rows)
		mock.ExpectExec(updateQuery).
			WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), login.ClientID, login.Realm, login.Name).
			WillReturnResult(sqlmock.NewResult(0, 1))

		tp, err := repo.LoginUser(login, config)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if tp == nil || tp.AccessToken == "" || tp.RefreshToken == "" {
			t.Errorf("expected valid token pair, got %v", tp)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("OTPEnabledReturnsChallengeOnly", func(t *testing.T) {
		login := &User{ClientID: "client1", Realm: "test", Name: "user1", Password: PtrFacade("password123")}
		hashedPassword := auth.HashPassword(login.Password)
		rows := sqlmock.NewRows([]string{"client_id", "realm", "name", "password", "otp_enabled", "otp_secret", "enc_key"}).
			AddRow("client1", "test", "user1", *hashedPassword, true, "encrypted-secret", "wrapped-key")
		mock.ExpectQuery(lookupQuery).
			WithArgs(login.ClientID, login.Realm, login.Name).
			WillReturnRows(rows)

		result, err := repo.LoginUser(login, config)
		if err != nil {
			t.Fatalf("expected challenge token, got error %v", err)
		}
		if result == nil || result.AccessToken == "" || result.RefreshToken != "" || result.AccessTokenLifetime != 0 {
			t.Fatalf("expected challenge-only response, got %+v", result)
		}
		claims, err := auth.VerifyChallengeToken(result.AccessToken, config.Realms["test"].VerificationPublicKey, "test")
		if err != nil {
			t.Fatalf("expected valid challenge token, got %v", err)
		}
		if claims["client_id"] != login.ClientID || claims["sub"] != login.Name {
			t.Fatalf("unexpected challenge claims: %v", claims)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("UserNotFound", func(t *testing.T) {
		login := &User{ClientID: "client1", Realm: "test", Name: "user1", Password: PtrFacade("password123")}
		mock.ExpectQuery(lookupQuery).
			WithArgs(login.ClientID, login.Realm, login.Name).
			WillReturnError(sql.ErrNoRows)

		tp, err := repo.LoginUser(login, config)
		if !errors.Is(err, errCredentialsDenied) || !strings.Contains(err.Error(), "user is not known") {
			t.Errorf("expected user not known credentials error, got %v", err)
		}
		if tp != nil {
			t.Errorf("expected nil token pair, got %v", tp)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("InvalidPassword", func(t *testing.T) {
		login := &User{ClientID: "client1", Realm: "test", Name: "user1", Password: PtrFacade("password123")}
		hashedPassword := auth.HashPassword(PtrFacade("wrongpassword"))
		rows := sqlmock.NewRows([]string{"client_id", "realm", "name", "password", "access", "is_active"}).
			AddRow("client1", "test", "user1", *hashedPassword, `{"key":"value"}`, true)
		mock.ExpectQuery(lookupQuery).
			WithArgs(login.ClientID, login.Realm, login.Name).
			WillReturnRows(rows)

		tp, err := repo.LoginUser(login, config)
		if !errors.Is(err, errCredentialsDenied) || !strings.Contains(err.Error(), "password invalid") {
			t.Errorf("expected password invalid credentials error, got %v", err)
		}
		if tp != nil {
			t.Errorf("expected nil token pair, got %v", tp)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("ExpiredPassword", func(t *testing.T) {
		login := &User{ClientID: "client1", Realm: "test", Name: "user1", Password: PtrFacade("password123")}
		hashedPassword := auth.HashPassword(login.Password)
		expiry := time.Now().Add(-time.Minute)
		rows := sqlmock.NewRows([]string{"client_id", "realm", "name", "password", "pwd_expiry", "is_active"}).
			AddRow("client1", "test", "user1", *hashedPassword, expiry, true)
		mock.ExpectQuery(lookupQuery).
			WithArgs(login.ClientID, login.Realm, login.Name).
			WillReturnRows(rows)

		tp, err := repo.LoginUser(login, config)
		if tp != nil {
			t.Errorf("expected nil token pair, got %v", tp)
		}
		if !errors.Is(err, errPasswordExpired) {
			t.Errorf("expected password expired error, got %v", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("UpdateError", func(t *testing.T) {
		login := &User{ClientID: "client1", Realm: "test", Name: "user1", Password: PtrFacade("password123")}
		hashedPassword := auth.HashPassword(login.Password)
		access, encKey := encryptedAccessFixture(t, login.Realm, login.ClientID, login.Name, `{"key":"value"}`)
		rows := sqlmock.NewRows([]string{"client_id", "realm", "name", "password", "access", "is_active", "enc_key"}).
			AddRow("client1", "test", "user1", *hashedPassword, access, true, encKey)
		mock.ExpectQuery(lookupQuery).
			WithArgs(login.ClientID, login.Realm, login.Name).
			WillReturnRows(rows)
		mock.ExpectExec(updateQuery).
			WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), login.ClientID, login.Realm, login.Name).
			WillReturnError(errors.New("update error"))

		tp, err := repo.LoginUser(login, config)
		if err == nil || err.Error() != "update error" {
			t.Errorf("expected update error, got %v", err)
		}
		if tp != nil {
			t.Errorf("expected nil token pair, got %v", tp)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})
}

func TestRefreshToken(t *testing.T) {
	const lookupQuery = "SELECT \\* from [\\w_]*.users WHERE client_id = \\? AND realm = \\? AND name = \\?"
	const updateQuery = "UPDATE [\\w_]*.users SET last_refresh = \\?, jti_refresh = \\? WHERE client_id = \\? AND realm = \\? AND name = \\?"
	db, mock := setupTestDB(t)
	defer db.Close()
	repo := &Repo{db: db, masterKey: repoTestMasterKey}
	config := setupTestConfig()

	t.Run("Success", func(t *testing.T) {
		iat := time.Now().Unix() - 100
		claims := jwt.MapClaims{
			"client_id": "client1",
			"sub":       "user1",
			"iat":       float64(iat),
			"sid":       "session1",
			"sex":       float64(iat + 600),
			"jti":       "refresh-jti-1",
		}
		realm := "test"
		access, encKey := encryptedAccessFixture(t, realm, "client1", "user1", `{"key":"value"}`)
		rows := sqlmock.NewRows([]string{"client_id", "realm", "name", "last_refresh", "jti_refresh", "access", "enc_key"}).
			AddRow("client1", "test", "user1", iat, "refresh-jti-1", access, encKey)
		mock.ExpectQuery(lookupQuery).
			WithArgs("client1", realm, "user1").
			WillReturnRows(rows)
		mock.ExpectExec(updateQuery).
			WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), "client1", realm, "user1").
			WillReturnResult(sqlmock.NewResult(0, 1))

		tp, err := repo.RefreshToken(claims, realm, config)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if tp == nil || tp.AccessToken == "" || tp.RefreshToken == "" {
			t.Errorf("expected valid token pair, got %v", tp)
		} else if tokenClaims, err := auth.VerifyToken(tp.AccessToken, config.Realms[realm].VerificationPublicKey, nil); err != nil {
			t.Errorf("expected a verifiable access token, got %v", err)
		} else if access, ok := tokenClaims["access"].(map[string]any); !ok || access["key"] != "value" {
			t.Errorf("expected access claim to be populated, got %v", tokenClaims["access"])
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("InvalidClientID", func(t *testing.T) {
		claims := jwt.MapClaims{"sub": "user1", "iat": float64(time.Now().Unix() - 100)}
		realm := "test"
		tp, err := repo.RefreshToken(claims, realm, config)
		if err == nil || err.Error() != "access denied - client_id claim is not valid" {
			t.Errorf("expected client_id error, got %v", err)
		}
		if tp != nil {
			t.Errorf("expected nil token pair, got %v", tp)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("InvalidSub", func(t *testing.T) {
		claims := jwt.MapClaims{"client_id": "client1", "iat": float64(time.Now().Unix() - 100)}
		realm := "test"
		tp, err := repo.RefreshToken(claims, realm, config)
		if err == nil || err.Error() != "access denied - sub claim is not valid" {
			t.Errorf("expected sub error, got %v", err)
		}
		if tp != nil {
			t.Errorf("expected nil token pair, got %v", tp)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("InvalidIat", func(t *testing.T) {
		claims := jwt.MapClaims{"client_id": "client1", "sub": "user1", "iat": "invalid", "jti": "refresh-jti-1"}
		realm := "test"
		rows := sqlmock.NewRows([]string{"client_id", "realm", "name", "last_refresh", "jti_refresh"}).
			AddRow("client1", "test", "user1", 1234567890, "refresh-jti-1")
		mock.ExpectQuery(lookupQuery).
			WithArgs("client1", realm, "user1").
			WillReturnRows(rows)

		tp, err := repo.RefreshToken(claims, realm, config)
		if err == nil || err.Error() != "access denied - issued at claim is not valid" {
			t.Errorf("expected invalid refresh token error, got %v", err)
		}
		if tp != nil {
			t.Errorf("expected nil token pair, got %v", tp)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("TokenReuse", func(t *testing.T) {
		claims := jwt.MapClaims{"client_id": "client1", "sub": "user1", "iat": float64(1234567890), "jti": "refresh-jti-1"}
		realm := "test"
		rows := sqlmock.NewRows([]string{"client_id", "realm", "name", "last_refresh", "jti_refresh"}).
			AddRow("client1", "test", "user1", 1234567891, "refresh-jti-1")
		mock.ExpectQuery(lookupQuery).
			WithArgs("client1", realm, "user1").
			WillReturnRows(rows)

		tp, err := repo.RefreshToken(claims, realm, config)
		if err == nil || err.Error() != "access denied - token cannot be reused" {
			t.Errorf("expected token reuse error, got %v", err)
		}
		if tp != nil {
			t.Errorf("expected nil token pair, got %v", tp)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("NoLastRefresh", func(t *testing.T) {
		claims := jwt.MapClaims{"client_id": "client1", "sub": "user1", "iat": float64(1234567890), "jti": "refresh-jti-1"}
		realm := "test"
		rows := sqlmock.NewRows([]string{"client_id", "realm", "name", "last_refresh", "jti_refresh"}).
			AddRow("client1", "test", "user1", nil, "refresh-jti-1")
		mock.ExpectQuery(lookupQuery).
			WithArgs("client1", realm, "user1").
			WillReturnRows(rows)

		tp, err := repo.RefreshToken(claims, realm, config)
		if err == nil || err.Error() != "access denied - token cannot be reused" {
			t.Errorf("expected token reuse error, got %v", err)
		}
		if tp != nil {
			t.Errorf("expected nil token pair, got %v", tp)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("QueryError", func(t *testing.T) {
		claims := jwt.MapClaims{"client_id": "client1", "sub": "user1", "iat": float64(1234567890), "jti": "refresh-jti-1"}
		realm := "test"
		mock.ExpectQuery(lookupQuery).
			WithArgs("client1", realm, "user1").
			WillReturnError(errors.New("db error"))

		tp, err := repo.RefreshToken(claims, realm, config)
		if err == nil || err.Error() != "db error" {
			t.Errorf("expected db error, got %v", err)
		}
		if tp != nil {
			t.Errorf("expected nil token pair, got %v", tp)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("UpdateError", func(t *testing.T) {
		claims := jwt.MapClaims{"client_id": "client1", "sub": "user1", "iat": float64(1234567890), "sid": "session1", "sex": float64(time.Now().Unix() + 600), "jti": "refresh-jti-1"}
		realm := "test"
		rows := sqlmock.NewRows([]string{"client_id", "realm", "name", "last_refresh", "jti_refresh"}).
			AddRow("client1", "test", "user1", 1234567890, "refresh-jti-1")
		mock.ExpectQuery(lookupQuery).
			WithArgs("client1", realm, "user1").
			WillReturnRows(rows)
		mock.ExpectExec(updateQuery).
			WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), "client1", realm, "user1").
			WillReturnError(errors.New("update error"))

		tp, err := repo.RefreshToken(claims, realm, config)
		if err == nil || err.Error() != "update error" {
			t.Errorf("expected update error, got %v", err)
		}
		if tp != nil {
			t.Errorf("expected nil token pair, got %v", tp)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})
}

func TestLogoutUser(t *testing.T) {
	const updateQuery = "UPDATE [\\w_]*.users SET last_refresh = NULL, jti_refresh = NULL WHERE client_id = \\? AND realm = \\? AND name = \\?"
	db, mock := setupTestDB(t)
	defer db.Close()
	repo := &Repo{db: db}

	t.Run("Success", func(t *testing.T) {
		claims := jwt.MapClaims{"client_id": "client1", "sub": "user1"}
		realm := "test"
		mock.ExpectExec(updateQuery).
			WithArgs("client1", realm, "user1").
			WillReturnResult(sqlmock.NewResult(0, 1))

		err := repo.LogoutUser(claims, realm)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("InvalidClientID", func(t *testing.T) {
		claims := jwt.MapClaims{"sub": "user1"}
		realm := "test"
		err := repo.LogoutUser(claims, realm)
		if err == nil || err.Error() != "client_id claim is not valid" {
			t.Errorf("expected client_id error, got %v", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("InvalidSub", func(t *testing.T) {
		claims := jwt.MapClaims{"client_id": "client1"}
		realm := "test"
		err := repo.LogoutUser(claims, realm)
		if err == nil || err.Error() != "sub claim is not valid" {
			t.Errorf("expected sub error, got %v", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("NoRowsAffected", func(t *testing.T) {
		claims := jwt.MapClaims{"client_id": "client1", "sub": "user1"}
		realm := "test"
		mock.ExpectExec(updateQuery).
			WithArgs("client1", realm, "user1").
			WillReturnResult(sqlmock.NewResult(0, 0))

		err := repo.LogoutUser(claims, realm)
		if err == nil || err.Error() != "user not found" {
			t.Errorf("expected user not found error, got %v", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("ExecError", func(t *testing.T) {
		claims := jwt.MapClaims{"client_id": "client1", "sub": "user1"}
		realm := "test"
		mock.ExpectExec(updateQuery).
			WithArgs("client1", realm, "user1").
			WillReturnError(errors.New("db error"))

		err := repo.LogoutUser(claims, realm)
		if err == nil || err.Error() != "db error" {
			t.Errorf("expected db error, got %v", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})
}

func TestOTPLogin(t *testing.T) {
	const query = "SELECT \\* from [\\w_]*.users WHERE client_id = \\? AND realm = \\? AND name = \\? AND is_active = true"
	const updateQuery = "UPDATE [\\w_]*.users SET last_login = \\?, last_refresh = \\?, jti_refresh = \\? WHERE client_id = \\? AND realm = \\? AND name = \\?"
	db, mock := setupTestDB(t)
	defer db.Close()
	repo := &Repo{db: db, dbName: "testdb", masterKey: repoTestMasterKey}
	config := setupTestConfig()
	otpSecret := gotp.RandomSecret(20)
	totp := gotp.NewDefaultTOTP(otpSecret)
	owner := auth.OwnerContext("user", "test", "client1", "user1")
	dataKey, wrappedKey, err := auth.GenerateWrappedDataKey(repoTestMasterKey, owner)
	if err != nil {
		t.Fatal(err)
	}
	encryptedSecret, err := auth.EncryptOTPSecret(otpSecret, dataKey, owner)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("Success", func(t *testing.T) {
		login := OTPLogin{ClientID: "client1", Name: "user1", OTP: totp.Now()}
		realm := "test"
		rows := sqlmock.NewRows([]string{"client_id", "realm", "name", "otp_secret", "otp_enabled", "enc_key"}).
			AddRow("client1", "test", "user1", encryptedSecret, true, wrappedKey)
		mock.ExpectQuery(query).
			WithArgs(login.ClientID, realm, login.Name).
			WillReturnRows(rows)
		mock.ExpectExec(updateQuery).
			WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), login.ClientID, realm, login.Name).
			WillReturnResult(sqlmock.NewResult(0, 1))
		tokenPair, err := repo.OTPLogin(realm, login, config)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if tokenPair == nil || tokenPair.AccessToken == "" || tokenPair.RefreshToken == "" {
			t.Errorf("expected token pair, got %v", tokenPair)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("DisabledOTP", func(t *testing.T) {
		login := OTPLogin{ClientID: "client1", Name: "user1", OTP: totp.Now()}
		realm := "test"
		rows := sqlmock.NewRows([]string{"client_id", "realm", "name", "otp_secret", "otp_enabled", "enc_key"}).
			AddRow("client1", "test", "user1", encryptedSecret, false, wrappedKey)
		mock.ExpectQuery(query).
			WithArgs(login.ClientID, realm, login.Name).
			WillReturnRows(rows)

		tokenPair, err := repo.OTPLogin(realm, login, config)
		if !errors.Is(err, errOTPDenied) {
			t.Errorf("expected OTP denied error, got %v", err)
		}
		if tokenPair != nil {
			t.Errorf("expected no token pair, got %v", tokenPair)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("UserNotFound", func(t *testing.T) {
		login := OTPLogin{ClientID: "client1", Name: "user1", OTP: totp.Now()}
		realm := "test"
		mock.ExpectQuery(query).
			WithArgs(login.ClientID, realm, login.Name).
			WillReturnError(sql.ErrNoRows)

		tokenPair, err := repo.OTPLogin(realm, login, config)
		if !errors.Is(err, errOTPDenied) {
			t.Errorf("expected OTP denied error, got %v", err)
		}
		if tokenPair != nil {
			t.Errorf("expected no token pair, got %v", tokenPair)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("NoOTPSecret", func(t *testing.T) {
		login := OTPLogin{ClientID: "client1", Name: "user1", OTP: totp.Now()}
		realm := "test"
		rows := sqlmock.NewRows([]string{"client_id", "realm", "name", "otp_secret", "otp_enabled"}).
			AddRow("client1", "test", "user1", nil, true)
		mock.ExpectQuery(query).
			WithArgs(login.ClientID, realm, login.Name).
			WillReturnRows(rows)

		tokenPair, err := repo.OTPLogin(realm, login, config)
		if err == nil || errors.Is(err, errOTPDenied) {
			t.Errorf("expected internal OTP configuration error, got %v", err)
		}
		if tokenPair != nil {
			t.Errorf("expected no token pair, got %v", tokenPair)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("InvalidOTP", func(t *testing.T) {
		login := OTPLogin{ClientID: "client1", Name: "user1", OTP: "123456"}
		realm := "test"
		rows := sqlmock.NewRows([]string{"client_id", "realm", "name", "otp_secret", "otp_enabled", "enc_key"}).
			AddRow("client1", "test", "user1", encryptedSecret, true, wrappedKey)
		mock.ExpectQuery(query).
			WithArgs(login.ClientID, realm, login.Name).
			WillReturnRows(rows)

		tokenPair, err := repo.OTPLogin(realm, login, config)
		if !errors.Is(err, errOTPDenied) {
			t.Errorf("expected OTP denied error, got %v", err)
		}
		if tokenPair != nil {
			t.Errorf("expected no token pair, got %v", tokenPair)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})
}

func TestOTPLoginPostgresUsesBooleanPredicate(t *testing.T) {
	db, mock := setupTestDB(t)
	defer db.Close()
	repo := &Repo{db: sqlx.NewDb(db.DB, "pgx")}
	query := "SELECT \\* from users WHERE client_id = \\$1 AND realm = \\$2 AND name = \\$3 AND is_active = true"
	mock.ExpectQuery(query).
		WithArgs("client1", "test", "user1").
		WillReturnRows(sqlmock.NewRows([]string{"client_id"}))

	_, err := repo.OTPLogin("test", OTPLogin{ClientID: "client1", Name: "user1"}, setupTestConfig())
	if !errors.Is(err, errOTPDenied) {
		t.Fatalf("expected OTP denied after no user row, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unfulfilled expectations: %v", err)
	}
}
