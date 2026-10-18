package app

import (
	"net/url"
	"testing"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDatabaseConnectionParams_DefaultsToMySQL ensures empty driver settings retain MySQL defaults.
func TestDatabaseConnectionParams_DefaultsToMySQL(t *testing.T) {
	config := &Config{}
	config.DB.Host = "localhost"
	config.DB.User = "test-user"
	config.DB.Password = "p@ss word"
	config.DB.Port = 3306
	config.DB.Database = "gatekeeper"

	driver, dsn, err := databaseConnectionParams(config)
	require.NoError(t, err)
	assert.Equal(t, "mysql", driver)

	mysqlConfig, err := mysql.ParseDSN(dsn)
	require.NoError(t, err)
	assert.Equal(t, "test-user", mysqlConfig.User)
	assert.Equal(t, "p@ss word", mysqlConfig.Passwd)
	assert.Equal(t, "localhost:3306", mysqlConfig.Addr)
	assert.Equal(t, "gatekeeper", mysqlConfig.DBName)
	assert.True(t, mysqlConfig.ParseTime)
	assert.True(t, mysqlConfig.ClientFoundRows)
}

// TestDatabaseConnectionParams_PostgresTLS checks verified TLS and escaped PostgreSQL credentials.
func TestDatabaseConnectionParams_PostgresTLS(t *testing.T) {
	config := &Config{}
	config.DB.Driver = "postgres"
	config.DB.Host = "db.example.test"
	config.DB.User = "test-user"
	config.DB.Password = "p@ss:/word"
	config.DB.Port = 5432
	config.DB.Database = "gatekeeper"
	config.DB.TLS.Enabled = true

	driver, dsn, err := databaseConnectionParams(config)
	require.NoError(t, err)
	assert.Equal(t, "pgx", driver)
	parsed, err := url.Parse(dsn)
	require.NoError(t, err)
	password, ok := parsed.User.Password()
	require.True(t, ok)
	assert.Equal(t, "p@ss:/word", password)
	assert.Equal(t, "/gatekeeper", parsed.Path)
	assert.Equal(t, "verify-full", parsed.Query().Get("sslmode"))
	assert.Equal(t, "system", parsed.Query().Get("sslrootcert"))

	pgxConfig, err := pgx.ParseConfig(dsn)
	require.NoError(t, err)
	require.NotNil(t, pgxConfig.TLSConfig)
	assert.Equal(t, "db.example.test", pgxConfig.TLSConfig.ServerName)
	assert.False(t, pgxConfig.TLSConfig.InsecureSkipVerify)
}

// TestDatabaseConnectionParams_MySQLTLS checks the registered verified-TLS configuration.
func TestDatabaseConnectionParams_MySQLTLS(t *testing.T) {
	config := &Config{}
	config.DB.Host = "db.example.test"
	config.DB.User = "test-user"
	config.DB.Password = "test-password"
	config.DB.Port = 3306
	config.DB.Database = "gatekeeper"
	config.DB.TLS.Enabled = true

	driver, dsn, err := databaseConnectionParams(config)
	require.NoError(t, err)
	assert.Equal(t, "mysql", driver)
	mysqlConfig, err := mysql.ParseDSN(dsn)
	require.NoError(t, err)
	assert.Equal(t, mysqlTLSConfigName, mysqlConfig.TLSConfig)
}

func TestDatabaseConnectionParams_MySQLTLSSkipVerify(t *testing.T) {
	config := &Config{}
	config.DB.Host = "db.example.test"
	config.DB.User = "test-user"
	config.DB.Password = "test-password"
	config.DB.Port = 3306
	config.DB.Database = "gatekeeper"
	config.DB.TLS.Enabled = true
	config.DB.TLS.SkipVerify = true

	driver, dsn, err := databaseConnectionParams(config)
	require.NoError(t, err)
	assert.Equal(t, "mysql", driver)
	mysqlConfig, err := mysql.ParseDSN(dsn)
	require.NoError(t, err)
	assert.Equal(t, mysqlSkipVerifyTLSConfigName, mysqlConfig.TLSConfig)
}

func TestDatabaseConnectionParams_PostgresTLSSkipVerify(t *testing.T) {
	config := &Config{}
	config.DB.Driver = "postgres"
	config.DB.Host = "db.example.test"
	config.DB.User = "test-user"
	config.DB.Password = "test-password"
	config.DB.Port = 5432
	config.DB.Database = "gatekeeper"
	config.DB.TLS.Enabled = true
	config.DB.TLS.SkipVerify = true

	driver, dsn, err := databaseConnectionParams(config)
	require.NoError(t, err)
	assert.Equal(t, "pgx", driver)
	parsed, err := url.Parse(dsn)
	require.NoError(t, err)
	assert.Equal(t, "require", parsed.Query().Get("sslmode"))
	assert.Empty(t, parsed.Query().Get("sslrootcert"))

	pgxConfig, err := pgx.ParseConfig(dsn)
	require.NoError(t, err)
	require.NotNil(t, pgxConfig.TLSConfig)
	assert.True(t, pgxConfig.TLSConfig.InsecureSkipVerify)
}

// TestDatabaseConnectionParams_RejectsInvalidCACertificate rejects unreadable CA files.
func TestDatabaseConnectionParams_RejectsInvalidCACertificate(t *testing.T) {
	config := &Config{}
	config.DB.Driver = "postgres"
	config.DB.TLS.CACert = "/path/that/does/not/exist"

	_, _, err := databaseConnectionParams(config)
	require.ErrorContains(t, err, "load database TLS CA certificate")
}
