package auth

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseMasterKey(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	parsed, err := ParseMasterKey(base64.StdEncoding.EncodeToString(key))
	require.NoError(t, err)
	require.Equal(t, key, parsed)

	_, err = ParseMasterKey("not-base64")
	require.Error(t, err)
	_, err = ParseMasterKey(base64.StdEncoding.EncodeToString(key[:16]))
	require.Error(t, err)
}

func TestOwnerContextIsUnambiguous(t *testing.T) {
	assert.Equal(t, "4:user6:client3:123", OwnerContext("user", "client", "123"))
	assert.NotEqual(t, OwnerContext("ab", "c"), OwnerContext("a", "bc"))
}

func TestWrappedDataKeyRejectsInvalidInputs(t *testing.T) {
	key := bytes.Repeat([]byte{3}, 32)
	dataKey := bytes.Repeat([]byte{4}, 32)

	_, _, err := GenerateWrappedDataKey(key[:16], "owner")
	require.Error(t, err)
	_, err = WrapDataKey(dataKey[:16], key, "owner")
	require.Error(t, err)
	_, err = WrapDataKey(dataKey, key[:16], "owner")
	require.Error(t, err)
	_, err = UnwrapDataKey("", key, "owner")
	require.Error(t, err)
	_, err = UnwrapDataKey("v2.payload", key, "owner")
	require.Error(t, err)
	_, err = UnwrapDataKey("v1.!", key, "owner")
	require.Error(t, err)
	_, err = UnwrapDataKey("v1.AA", key, "owner")
	require.Error(t, err)
	_, err = UnwrapDataKey("v1.AA", key[:16], "owner")
	require.Error(t, err)
}

func TestOTPSecretRejectsInvalidInputs(t *testing.T) {
	key := bytes.Repeat([]byte{5}, 32)
	_, err := EncryptOTPSecret("", key, "owner")
	require.Error(t, err)
	_, err = EncryptOTPSecret("secret", key[:16], "owner")
	require.Error(t, err)
	_, err = DecryptOTPSecret("", key, "owner")
	require.Error(t, err)
	_, err = DecryptOTPSecret("v2.payload", key, "owner")
	require.Error(t, err)
	_, err = DecryptOTPSecret("v1.!", key, "owner")
	require.Error(t, err)
	_, err = DecryptOTPSecret("v1.AA", key[:16], "owner")
	require.Error(t, err)

	_, err = deriveEntityKey(key[:16], "otp")
	require.Error(t, err)
	_, err = encryptWithKey([]byte("data"), key[:16], nil)
	require.Error(t, err)
	_, err = decryptWithKey([]byte("short"), key, nil)
	require.Error(t, err)
	_, err = decryptWithKey([]byte("short"), key[:16], nil)
	require.Error(t, err)
}

type failingRandomReader struct {
	remaining int
}

func (reader *failingRandomReader) Read(buffer []byte) (int, error) {
	if reader.remaining == 0 {
		return 0, errors.New("random source unavailable")
	}
	count := len(buffer)
	if count > reader.remaining {
		count = reader.remaining
	}
	for index := 0; index < count; index++ {
		buffer[index] = byte(index + 1)
	}
	reader.remaining -= count
	return count, nil
}

func TestCryptoHelpersPropagateRandomSourceErrors(t *testing.T) {
	originalReader := rand.Reader
	rand.Reader = &failingRandomReader{remaining: 0}
	t.Cleanup(func() { rand.Reader = originalReader })

	key := bytes.Repeat([]byte{6}, 32)
	_, _, err := GenerateWrappedDataKey(key, "owner")
	require.Error(t, err)
	_, err = WrapDataKey(key, key, "owner")
	require.Error(t, err)
	_, err = EncryptOTPSecret("secret", key, "owner")
	require.Error(t, err)

	rand.Reader = &failingRandomReader{remaining: 32}
	_, _, err = GenerateWrappedDataKey(key, "owner")
	require.Error(t, err)
}

func TestWrappedDataKeyAndOTPSecret(t *testing.T) {
	masterKey := bytes.Repeat([]byte{1}, 32)
	owner := "user:realm:client:user"
	dataKey, wrapped, err := GenerateWrappedDataKey(masterKey, owner)
	require.NoError(t, err)
	require.Len(t, dataKey, 32)

	unwrapped, err := UnwrapDataKey(wrapped, masterKey, owner)
	require.NoError(t, err)
	require.Equal(t, dataKey, unwrapped)

	encrypted, err := EncryptOTPSecret("JBSWY3DPEHPK3PXP", dataKey, owner)
	require.NoError(t, err)
	decrypted, err := DecryptOTPSecret(encrypted, dataKey, owner)
	require.NoError(t, err)
	require.Equal(t, "JBSWY3DPEHPK3PXP", decrypted)

	_, err = UnwrapDataKey(wrapped, masterKey, "user:other:owner")
	require.Error(t, err)
	_, err = DecryptOTPSecret(encrypted, dataKey, "user:other:owner")
	require.Error(t, err)
}

func TestDecryptOTPSecretRejectsTampering(t *testing.T) {
	key := bytes.Repeat([]byte{2}, 32)
	encrypted, err := EncryptOTPSecret("secret-value", key, "client:realm:id")
	require.NoError(t, err)

	payload, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(encrypted, "v1."))
	require.NoError(t, err)
	payload[len(payload)-1] ^= 1
	modified := "v1." + base64.RawStdEncoding.EncodeToString(payload)
	_, err = DecryptOTPSecret(modified, key, "client:realm:id")
	require.Error(t, err)
}

func TestEncryptAccess(t *testing.T) {
	masterKey := bytes.Repeat([]byte{3}, 32)
	owner := OwnerContext("client", "realm", "client-id")
	dataKey, wrapped, err := GenerateWrappedDataKey(masterKey, owner)
	require.NoError(t, err)
	encrypted, err := EncryptAccess(`{"canWrite":true}`, dataKey, owner)
	require.NoError(t, err)
	require.NotEqual(t, `{"canWrite":true}`, encrypted)

	unwrapped, err := UnwrapDataKey(wrapped, masterKey, owner)
	require.NoError(t, err)
	decrypted, err := DecryptAccess(encrypted, unwrapped, owner)
	require.NoError(t, err)
	require.Equal(t, `{"canWrite":true}`, decrypted)

	_, err = DecryptAccess(encrypted, unwrapped, OwnerContext("client", "realm", "other"))
	require.Error(t, err)

	payload, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(encrypted, "v1."))
	require.NoError(t, err)
	payload[len(payload)-1] ^= 1
	modified := "v1." + base64.RawStdEncoding.EncodeToString(payload)
	_, err = DecryptAccess(modified, unwrapped, owner)
	require.Error(t, err)
}
