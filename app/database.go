package app

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"

	"github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/jmoiron/sqlx"
)

const (
	mysqlTLSConfigName           = "gatekeeper-verified-tls"
	mysqlSkipVerifyTLSConfigName = "gatekeeper-skip-verify-tls"
)

// databaseConnectionParams selects the SQL driver and builds its connection string.
func databaseConnectionParams(config *Config) (string, string, error) {
	driver := config.DB.Driver
	if driver == "" {
		driver = "mysql"
	}
	if driver != "mysql" && driver != "postgres" {
		return "", "", fmt.Errorf("unsupported database driver %q", driver)
	}
	if config.DB.TLS.CACert != "" && !config.DB.TLS.SkipVerify {
		if _, err := loadRootCAs(config.DB.TLS.CACert); err != nil {
			return "", "", fmt.Errorf("load database TLS CA certificate: %w", err)
		}
	}

	switch driver {
	case "mysql":
		mysqlConfig := mysql.Config{
			User:            config.DB.User,
			Passwd:          config.DB.Password,
			Net:             "tcp",
			Addr:            net.JoinHostPort(config.DB.Host, strconv.Itoa(config.DB.Port)),
			DBName:          config.DB.Database,
			ParseTime:       true,
			ClientFoundRows: true,

			AllowNativePasswords: true,
		}
		if config.DB.TLS.Enabled {
			var roots *x509.CertPool
			tlsConfigName := mysqlTLSConfigName
			if !config.DB.TLS.SkipVerify {
				var err error
				roots, err = loadRootCAs(config.DB.TLS.CACert)
				if err != nil {
					return "", "", fmt.Errorf("load database TLS CA certificate: %w", err)
				}
			} else {
				tlsConfigName = mysqlSkipVerifyTLSConfigName
			}
			if err := mysql.RegisterTLSConfig(tlsConfigName, &tls.Config{
				MinVersion:         tls.VersionTLS12,
				ServerName:         config.DB.Host,
				RootCAs:            roots,
				InsecureSkipVerify: config.DB.TLS.SkipVerify, // #nosec G402 -- controlled by the explicit db.tls.skipVerify option
			}); err != nil {
				return "", "", fmt.Errorf("configure MySQL TLS: %w", err)
			}
			mysqlConfig.TLSConfig = tlsConfigName
		}
		return "mysql", mysqlConfig.FormatDSN(), nil

	case "postgres":
		query := url.Values{}
		if config.DB.TLS.Enabled {
			if config.DB.TLS.SkipVerify {
				query.Set("sslmode", "require")
			} else {
				query.Set("sslmode", "verify-full")
				if config.DB.TLS.CACert == "" {
					query.Set("sslrootcert", "system")
				} else {
					query.Set("sslrootcert", config.DB.TLS.CACert)
				}
			}
		} else {
			query.Set("sslmode", "disable")
		}
		dsn := (&url.URL{
			Scheme:   "postgres",
			User:     url.UserPassword(config.DB.User, config.DB.Password),
			Host:     net.JoinHostPort(config.DB.Host, strconv.Itoa(config.DB.Port)),
			Path:     "/" + config.DB.Database,
			RawQuery: query.Encode(),
		}).String()
		return "pgx", dsn, nil
	}
	return "", "", fmt.Errorf("unsupported database driver %q", driver)
}

// loadRootCAs loads system roots or the configured PEM CA certificate.
func loadRootCAs(caCertPath string) (*x509.CertPool, error) {
	if caCertPath == "" {
		roots, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("load system certificate pool: %w", err)
		}
		if roots == nil {
			roots = x509.NewCertPool()
		}
		return roots, nil
	}
	pem, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if ok := roots.AppendCertsFromPEM(pem); !ok {
		return nil, fmt.Errorf("CA certificate file %q contains no valid PEM certificates", caCertPath)
	}
	return roots, nil
}

// connectDatabase opens a database connection using the configured driver and TLS options.
func connectDatabase(connector DBConnector, config *Config) (*sqlx.DB, error) {
	driver, dsn, err := databaseConnectionParams(config)
	if err != nil {
		return nil, err
	}
	return connector(driver, dsn)
}
