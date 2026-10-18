package app

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const validMasterKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func configTestSigningKeys(seedByte byte) (string, string) {
	seed := bytes.Repeat([]byte{seedByte}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	return base64.StdEncoding.EncodeToString(seed),
		base64.StdEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey))
}

func writeTempConfigFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func withTempConfigDir(t *testing.T, configName, content string, testFunc func()) {
	t.Helper()
	tmpDir := t.TempDir()
	writeTempConfigFile(t, tmpDir, configName, content)
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldWd); err != nil {
			t.Error(err)
		}
	})
	testFunc()
}

func validConfigYAML(prettyPrint string) string {
	signingPrivateKey, verificationPublicKey := configTestSigningKeys(1)
	return `masterKey: "` + validMasterKey + `"` + "\n" +
		`server: {port: 8080, logLevel: info, logRequests: true, prettyPrint: ` + prettyPrint + `, apiKeyCacheTTL: 600}` + "\n" +
		`db: {host: localhost, user: test-user, password: test-password, port: 3306, database: test-db, timezone: UTC}` + "\n" +
		`realms: {api: {signingPrivateKey: ` + signingPrivateKey + `, verificationPublicKey: ` + verificationPublicKey + `}}` + "\n"
}

func unsetEnvForTest(t *testing.T, name string) {
	t.Helper()
	value, existed := os.LookupEnv(name)
	if err := os.Unsetenv(name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if existed {
			_ = os.Setenv(name, value)
		} else {
			_ = os.Unsetenv(name)
		}
	})
}

func TestReadConfig_PrettyPrint_FromYAML(t *testing.T) {
	t.Setenv("MASTER_KEY", validMasterKey)
	withTempConfigDir(t, "config.yml", validConfigYAML("true"), func() {
		cfg, err := ReadConfig()
		require.NoError(t, err)
		assert.True(t, cfg.Server.PrettyPrint)
	})
}

func TestReadConfig_PrettyPrint_FromEnv(t *testing.T) {
	t.Setenv("MASTER_KEY", validMasterKey)
	t.Setenv("SERVER_PRETTY_PRINT", "true")
	yamlContent := strings.Replace(validConfigYAML("false"), "prettyPrint: false", "prettyPrint: ${SERVER_PRETTY_PRINT}", 1)
	withTempConfigDir(t, "config.yml", yamlContent, func() {
		cfg, err := ReadConfig()
		require.NoError(t, err)
		assert.True(t, cfg.Server.PrettyPrint)
	})
}

func TestReadConfig_PrettyPrint_DefaultFalse(t *testing.T) {
	t.Setenv("MASTER_KEY", validMasterKey)
	withTempConfigDir(t, "config.yml", validConfigYAML("false"), func() {
		cfg, err := ReadConfig()
		require.NoError(t, err)
		assert.False(t, cfg.Server.PrettyPrint)
	})
}

func TestReadConfig_MasterKey_FromEnv(t *testing.T) {
	envMasterKey := "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	t.Setenv("MASTER_KEY", envMasterKey)
	yamlContent := strings.Replace(validConfigYAML("false"), `masterKey: "`+validMasterKey+`"`, `masterKey: ${MASTER_KEY}`, 1)
	withTempConfigDir(t, "config.yml", yamlContent, func() {
		cfg, err := ReadConfig()
		require.NoError(t, err)
		assert.Equal(t, envMasterKey, cfg.MasterKey)
	})
}

func TestReadConfig_MasterKey_FromYAML(t *testing.T) {
	unsetEnvForTest(t, "MASTER_KEY")
	withTempConfigDir(t, "config.yml", validConfigYAML("false"), func() {
		cfg, err := ReadConfig()
		require.NoError(t, err)
		assert.Equal(t, validMasterKey, cfg.MasterKey)
	})
}

func TestConfigValidate_RejectsMissingAndMalformedSecrets(t *testing.T) {
	cfg := &Config{}
	cfg.Realms = map[string]RealmConfig{"api": {}}
	err := cfg.validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "masterKey is required")
	assert.Contains(t, err.Error(), "db.user is required")
	assert.Contains(t, err.Error(), "db.password is required")
	assert.Contains(t, err.Error(), "realms.api.signingPrivateKey is required")
	assert.Contains(t, err.Error(), "realms.api.verificationPublicKey is required")

	cfg.MasterKey = "not-base64"
	err = cfg.validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "masterKey must be base64-encoded 32-byte key material")

	cfg.MasterKey = "dGVzdA=="
	err = cfg.validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "masterKey must be base64-encoded 32-byte key material")
}

func TestConfigValidate_RejectsMalformedRealmName(t *testing.T) {
	signingPrivateKey, verificationPublicKey := configTestSigningKeys(1)
	cfg := &Config{
		MasterKey: validMasterKey,
		Realms: map[string]RealmConfig{"mal:formed": {
			SigningPrivateKey: signingPrivateKey, VerificationPublicKey: verificationPublicKey,
		}},
	}
	err := cfg.validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "realms.mal:formed.name must not contain ':'")
}

func TestConfigValidate_RejectsMalformedRealmKey(t *testing.T) {
	_, verificationPublicKey := configTestSigningKeys(1)
	cfg := &Config{
		MasterKey: validMasterKey,
		Realms: map[string]RealmConfig{"api": {
			SigningPrivateKey: "not-base64", VerificationPublicKey: verificationPublicKey,
		}},
	}
	err := cfg.validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "realms.api.signingPrivateKey must be base64-encoded")
}

func TestConfigValidate_RejectsMismatchedRealmKeys(t *testing.T) {
	signingPrivateKey, _ := configTestSigningKeys(1)
	_, verificationPublicKey := configTestSigningKeys(2)
	cfg := &Config{
		MasterKey: validMasterKey,
		Realms: map[string]RealmConfig{"api": {
			SigningPrivateKey: signingPrivateKey, VerificationPublicKey: verificationPublicKey,
		}},
	}
	require.ErrorContains(t, cfg.validate(), "realms.api.verificationPublicKey does not match signingPrivateKey")
}

func TestConfigValidate_RejectsIncorrectEd25519KeySizes(t *testing.T) {
	cfg := &Config{
		MasterKey: validMasterKey,
		Realms: map[string]RealmConfig{"api": {
			SigningPrivateKey:     base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, ed25519.SeedSize-1)),
			VerificationPublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, ed25519.PublicKeySize-1)),
		}},
	}
	err := cfg.validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "realms.api.signingPrivateKey must encode a 32-byte Ed25519 seed")
	assert.Contains(t, err.Error(), "realms.api.verificationPublicKey must encode a 32-byte Ed25519 public key")
}

// TestConfigValidate_DatabaseOptions checks supported drivers and TLS CA dependencies.
func TestConfigValidate_DatabaseOptions(t *testing.T) {
	cfg := &Config{}
	cfg.DB.Driver = "sqlite"
	require.ErrorContains(t, cfg.validate(), "db.driver must be either mysql or postgres")

	cfg.DB.Driver = "postgres"
	cfg.DB.TLS.CACert = "/etc/ssl/db-ca.pem"
	require.ErrorContains(t, cfg.validate(), "db.tls.caCert requires db.tls.enabled")

	cfg.DB.TLS.Enabled = true
	require.NotContains(t, cfg.validate().Error(), "db.driver must be either mysql or postgres")

	cfg.DB.TLS.Enabled = false
	cfg.DB.TLS.SkipVerify = true
	require.ErrorContains(t, cfg.validate(), "db.tls.skipVerify requires db.tls.enabled")
}
