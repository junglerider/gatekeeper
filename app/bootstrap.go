package app

import (
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"junglerider/gatekeeper/datamodel"
)

// default account created by the bootstrap command
const (
	BootstrapRealm    = "internal"
	BootstrapClientID = "internal"
	BootstrapName     = "admin"
	BootstrapPassword = "admin"
)

var ErrAdminExists = errors.New("admin user already exists")

// access settings granting administrative rights
var BootstrapAccess = map[string]any{"gatekeeper": []any{"admin"}}

// persistence operations needed to bootstrap the admin account
type AdminStore interface {
	AdminExists(realm, clientID, name string) (bool, error)
	CreateAdmin(realm, clientID, name, password string, access any) error
}

// creates missing database tables
type SchemaCreator interface {
	EnsureSchema() error
}

// executes SQL statements and queries, satisfied by *sql.DB and *sqlx.DB
type SchemaDB interface {
	Exec(query string, args ...any) (sql.Result, error)
	Query(query string, args ...any) (*sql.Rows, error)
}

// creates the client and user tables if they do not exist yet
type Schema struct {
	DB     SchemaDB
	Driver string
}

func (s Schema) EnsureSchema() error {
	type tableDefinition struct {
		name        string
		ddl         string
		existsQuery string
	}
	var tables []tableDefinition
	switch s.Driver {
	case "", "mysql":
		tables = []tableDefinition{
			{"clients", datamodel.ClientsSQL, "SHOW TABLES LIKE ?"},
			{"users", datamodel.UsersSQL, "SHOW TABLES LIKE ?"},
		}
	case "postgres":
		tables = []tableDefinition{
			{"clients", datamodel.PostgresClientsSQL, "SELECT 1 WHERE to_regclass($1) IS NOT NULL"},
			{"users", datamodel.PostgresUsersSQL, "SELECT 1 WHERE to_regclass($1) IS NOT NULL"},
		}
	default:
		return fmt.Errorf("unsupported database driver %q", s.Driver)
	}
	for _, table := range tables {
		rows, err := s.DB.Query(table.existsQuery, table.name)
		if err != nil {
			return fmt.Errorf("check if %s table exists: %w", table.name, err)
		}
		exists := rows.Next()
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return fmt.Errorf("check if %s table exists: %w", table.name, err)
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("check if %s table exists: %w", table.name, err)
		}
		if exists {
			continue
		}
		if _, err := s.DB.Exec(table.ddl); err != nil {
			return fmt.Errorf("create %s table: %w", table.name, err)
		}
	}
	fmt.Printf("created or ensured users and clients database tables\n")
	return nil
}

// parses command line arguments and reports which standalone mode was requested
func ParseFlags(args []string) (bool, bool, error) {
	fs := flag.NewFlagSet("gatekeeper", flag.ContinueOnError)
	bootstrap := fs.Bool("bootstrap", false, "create the initial admin user in the internal realm and exit")
	genkeys := fs.Bool("genkeys", false, "generate an Ed25519 signing key pair and exit")
	if err := fs.Parse(args); err != nil {
		return false, false, err
	}
	return *bootstrap, *genkeys, nil
}

// creates missing tables, then the initial admin account unless it already exists
func Bootstrap(schema SchemaCreator, store AdminStore, config *Config) error {
	if _, ok := config.Realms[BootstrapRealm]; !ok {
		return fmt.Errorf("realm %q is not configured", BootstrapRealm)
	}
	if err := schema.EnsureSchema(); err != nil {
		return err
	}
	exists, err := store.AdminExists(BootstrapRealm, BootstrapClientID, BootstrapName)
	if err != nil {
		return fmt.Errorf("check for existing admin user: %w", err)
	}
	if exists {
		return ErrAdminExists
	}
	return store.CreateAdmin(BootstrapRealm, BootstrapClientID, BootstrapName, BootstrapPassword, BootstrapAccess)
}

// runs the bootstrap, reports the outcome and returns the process exit code
func RunBootstrap(schema SchemaCreator, store AdminStore, config *Config, stdout, stderr io.Writer) int {
	err := Bootstrap(schema, store, config)
	switch {
	case errors.Is(err, ErrAdminExists):
		fmt.Fprintf(stderr, "error: user %q (client id %q) already exists in realm %q\n", BootstrapName, BootstrapClientID, BootstrapRealm)
		return 1
	case err != nil:
		fmt.Fprintf(stderr, "error: bootstrap failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "created user %q (client id %q) in realm %q with the default password; change it immediately\n", BootstrapName, BootstrapClientID, BootstrapRealm)
	return 0
}
