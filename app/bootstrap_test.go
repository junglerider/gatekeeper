package app

import (
	"bytes"
	"errors"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"junglerider/gatekeeper/datamodel"
)

type fakeSchema struct{ err error }

func (f fakeSchema) EnsureSchema() error { return f.err }

type fakeStore struct {
	exists    bool
	existsErr error
	createErr error
	created   []string
	access    any
}

func (f *fakeStore) AdminExists(realm, clientID, name string) (bool, error) {
	return f.exists, f.existsErr
}

func (f *fakeStore) CreateAdmin(realm, clientID, name, password string, access any) error {
	f.created = []string{realm, clientID, name, password}
	f.access = access
	return f.createErr
}

func bootstrapConfig() *Config {
	return &Config{Realms: map[string]RealmConfig{"internal": {}}}
}

func TestParseFlags(t *testing.T) {
	on, genkeys, err := ParseFlags([]string{"-bootstrap"})
	assert.NoError(t, err)
	assert.True(t, on)
	assert.False(t, genkeys)
	on, genkeys, err = ParseFlags([]string{"--bootstrap"})
	assert.NoError(t, err)
	assert.True(t, on)
	assert.False(t, genkeys)
	on, genkeys, err = ParseFlags([]string{"--genkeys"})
	assert.NoError(t, err)
	assert.False(t, on)
	assert.True(t, genkeys)
	on, genkeys, err = ParseFlags([]string{"-genkeys"})
	assert.NoError(t, err)
	assert.False(t, on)
	assert.True(t, genkeys)
	on, genkeys, err = ParseFlags(nil)
	assert.NoError(t, err)
	assert.False(t, on)
	assert.False(t, genkeys)
	_, _, err = ParseFlags([]string{"-unknown"})
	assert.Error(t, err)
}

func TestBootstrap_CreatesAdmin(t *testing.T) {
	store := &fakeStore{}
	assert.NoError(t, Bootstrap(fakeSchema{}, store, bootstrapConfig()))
	assert.Equal(t, []string{"internal", "internal", "admin", "admin"}, store.created)
	assert.Equal(t, BootstrapAccess, store.access)
}

func TestBootstrap_AdminExists(t *testing.T) {
	store := &fakeStore{exists: true}
	assert.ErrorIs(t, Bootstrap(fakeSchema{}, store, bootstrapConfig()), ErrAdminExists)
	assert.Nil(t, store.created)
}

func TestBootstrap_LookupError(t *testing.T) {
	err := Bootstrap(fakeSchema{}, &fakeStore{existsErr: errors.New("db down")}, bootstrapConfig())
	assert.ErrorContains(t, err, "db down")
	assert.NotErrorIs(t, err, ErrAdminExists)
}

func TestBootstrap_RealmMissing(t *testing.T) {
	err := Bootstrap(fakeSchema{}, &fakeStore{}, &Config{Realms: map[string]RealmConfig{"api": {}}})
	assert.ErrorContains(t, err, "not configured")
}

func TestRunBootstrap(t *testing.T) {
	tests := []struct {
		name   string
		store  *fakeStore
		code   int
		stdout string
		stderr string
	}{
		{"success", &fakeStore{}, 0, "created user", ""},
		{"exists", &fakeStore{exists: true}, 1, "", "already exists"},
		{"failure", &fakeStore{createErr: errors.New("boom")}, 1, "", "boom"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			assert.Equal(t, tt.code, RunBootstrap(fakeSchema{}, tt.store, bootstrapConfig(), &out, &errOut))
			assert.Contains(t, out.String(), tt.stdout)
			assert.Contains(t, errOut.String(), tt.stderr)
		})
	}
}

func TestBootstrap_SchemaError(t *testing.T) {
	store := &fakeStore{}
	err := Bootstrap(fakeSchema{err: errors.New("no tables")}, store, bootstrapConfig())
	assert.ErrorContains(t, err, "no tables")
	assert.Nil(t, store.created)
}

func TestSchema_EnsureSchema(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery(regexp.QuoteMeta("SHOW TABLES LIKE ?")).
		WithArgs("clients").
		WillReturnRows(sqlmock.NewRows([]string{"Tables_in_test"}).AddRow("clients"))
	mock.ExpectQuery(regexp.QuoteMeta("SHOW TABLES LIKE ?")).
		WithArgs("users").
		WillReturnRows(sqlmock.NewRows([]string{"Tables_in_test"}).AddRow("users"))

	assert.NoError(t, Schema{DB: db}.EnsureSchema())
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSchema_CreatesMissingTable(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery(regexp.QuoteMeta("SHOW TABLES LIKE ?")).
		WithArgs("clients").
		WillReturnRows(sqlmock.NewRows([]string{"Tables_in_test"}).AddRow("clients"))
	mock.ExpectQuery(regexp.QuoteMeta("SHOW TABLES LIKE ?")).
		WithArgs("users").
		WillReturnRows(sqlmock.NewRows([]string{"Tables_in_test"}))
	mock.ExpectExec(regexp.QuoteMeta(datamodel.UsersSQL)).
		WillReturnResult(sqlmock.NewResult(0, 0))

	assert.NoError(t, Schema{DB: db}.EnsureSchema())
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSchema_EnsurePostgresSchema(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery(regexp.QuoteMeta("SELECT 1 WHERE to_regclass($1) IS NOT NULL")).
		WithArgs("clients").
		WillReturnRows(sqlmock.NewRows([]string{"?column?"}).AddRow(1))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT 1 WHERE to_regclass($1) IS NOT NULL")).
		WithArgs("users").
		WillReturnRows(sqlmock.NewRows([]string{"?column?"}))
	mock.ExpectExec(regexp.QuoteMeta(datamodel.PostgresUsersSQL)).
		WillReturnResult(sqlmock.NewResult(0, 0))

	assert.NoError(t, (Schema{DB: db, Driver: "postgres"}).EnsureSchema())
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSchema_ExistenceCheckError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery(regexp.QuoteMeta("SHOW TABLES LIKE ?")).
		WithArgs("clients").
		WillReturnError(errors.New("lookup failed"))

	err = Schema{DB: db}.EnsureSchema()
	assert.ErrorContains(t, err, "check if clients table exists")
	assert.ErrorContains(t, err, "lookup failed")
	assert.NoError(t, mock.ExpectationsWereMet())
}
