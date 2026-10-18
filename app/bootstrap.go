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

// executes SQL statements, satisfied by *sql.DB and *sqlx.DB
type Execer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

// creates the client and user tables if they do not exist yet
type Schema struct {
	DB     Execer
	Driver string
}

func (s Schema) EnsureSchema() error {
	var tables map[string]string
	switch s.Driver {
	case "", "mysql":
		tables = map[string]string{"clients": datamodel.ClientsSQL, "users": datamodel.UsersSQL}
	case "postgres":
		tables = map[string]string{"clients": datamodel.PostgresClientsSQL, "users": datamodel.PostgresUsersSQL}
	default:
		return fmt.Errorf("unsupported database driver %q", s.Driver)
	}
	for name, ddl := range tables {
		if _, err := s.DB.Exec(ddl); err != nil {
			return fmt.Errorf("create %s table: %w", name, err)
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
