package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const wrappedKeyVersion = "v1"

// decodes a base64-encoded 32-byte master key
func ParseMasterKey(encoded string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode master key: %w", err)
	}
	if len(key) != 32 {
		return nil, errors.New("master key must decode to exactly 32 bytes")
	}
	return key, nil
}

// builds an unambiguous context string for binding ciphertext to an entity
func OwnerContext(entity string, identifiers ...string) string {
	var context string
	for _, part := range append([]string{entity}, identifiers...) {
		context += fmt.Sprintf("%d:%s", len(part), part)
	}
	return context
}

// creates a random data key and encrypts it with masterKey
func GenerateWrappedDataKey(masterKey []byte, owner string) ([]byte, string, error) {
	if len(masterKey) != 32 {
		return nil, "", errors.New("master key must be exactly 32 bytes")
	}
	dataKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dataKey); err != nil {
		return nil, "", fmt.Errorf("generate data key: %w", err)
	}

	wrapped, err := WrapDataKey(dataKey, masterKey, owner)
	if err != nil {
		return nil, "", err
	}
	return dataKey, wrapped, nil
}

// encrypts an existing data key with the master key and owner context
func WrapDataKey(dataKey, masterKey []byte, owner string) (string, error) {
	if len(dataKey) != 32 {
		return "", errors.New("data key must be exactly 32 bytes")
	}
	if len(masterKey) != 32 {
		return "", errors.New("master key must be exactly 32 bytes")
	}
	wrapped, err := encryptWithKey(dataKey, masterKey, []byte("gatekeeper/enc-key/v1/"+owner))
	if err != nil {
		return "", fmt.Errorf("wrap data key: %w", err)
	}
	return wrappedKeyVersion + "." + base64.RawStdEncoding.EncodeToString(wrapped), nil
}

// decrypts a stored data key with its owner-bound master key
func UnwrapDataKey(wrapped string, masterKey []byte, owner string) ([]byte, error) {
	if len(masterKey) != 32 {
		return nil, errors.New("master key must be exactly 32 bytes")
	}
	const prefix = wrappedKeyVersion + "."
	if len(wrapped) <= len(prefix) || wrapped[:len(prefix)] != prefix {
		return nil, errors.New("unsupported wrapped key version")
	}
	payload, err := base64.RawStdEncoding.DecodeString(wrapped[len(prefix):])
	if err != nil {
		return nil, fmt.Errorf("decode wrapped key: %w", err)
	}
	dataKey, err := decryptWithKey(payload, masterKey, []byte("gatekeeper/enc-key/v1/"+owner))
	if err != nil {
		return nil, errors.New("unable to unwrap data key")
	}
	if len(dataKey) != 32 {
		return nil, errors.New("unwrapped data key has invalid length")
	}
	return dataKey, nil
}

// encrypts an OTP secret using a per-entity data key
func EncryptOTPSecret(secret string, dataKey []byte, owner string) (string, error) {
	if secret == "" {
		return "", errors.New("OTP secret is empty")
	}
	return encryptEntityData(secret, dataKey, owner, "otp", "OTP secret")
}

// decrypts an OTP secret using its per-entity data key
func DecryptOTPSecret(encrypted string, dataKey []byte, owner string) (string, error) {
	return decryptEntityData(encrypted, dataKey, owner, "otp", "OTP secret")
}

// encrypts an access document using a key derived from the entity data key
func EncryptAccess(access string, dataKey []byte, owner string) (string, error) {
	return encryptEntityData(access, dataKey, owner, "access", "access data")
}

// decrypts an access document using its entity data key
func DecryptAccess(encrypted string, dataKey []byte, owner string) (string, error) {
	return decryptEntityData(encrypted, dataKey, owner, "access", "access data")
}

// encrypts a string using a key derived from the entity data key and purpose
func encryptEntityData(plaintext string, dataKey []byte, owner, purpose, label string) (string, error) {
	key, err := deriveEntityKey(dataKey, purpose)
	if err != nil {
		return "", err
	}
	ciphertext, err := encryptWithKey([]byte(plaintext), key, []byte("gatekeeper/"+purpose+"/v1/"+owner))
	if err != nil {
		return "", fmt.Errorf("encrypt %s: %w", label, err)
	}
	return wrappedKeyVersion + "." + base64.RawStdEncoding.EncodeToString(ciphertext), nil
}

// decrypts a string using a key derived from the entity data key and purpose
func decryptEntityData(encrypted string, dataKey []byte, owner, purpose, label string) (string, error) {
	const prefix = wrappedKeyVersion + "."
	if len(encrypted) <= len(prefix) || encrypted[:len(prefix)] != prefix {
		return "", fmt.Errorf("unsupported encrypted %s version", label)
	}
	payload, err := base64.RawStdEncoding.DecodeString(encrypted[len(prefix):])
	if err != nil {
		return "", fmt.Errorf("decode encrypted %s: %w", label, err)
	}
	key, err := deriveEntityKey(dataKey, purpose)
	if err != nil {
		return "", err
	}
	plaintext, err := decryptWithKey(payload, key, []byte("gatekeeper/"+purpose+"/v1/"+owner))
	if err != nil {
		return "", fmt.Errorf("unable to decrypt %s", label)
	}
	return string(plaintext), nil
}

// derives a purpose-specific encryption key from the per-entity data key using HKDF
func deriveEntityKey(dataKey []byte, purpose string) ([]byte, error) {
	if len(dataKey) != 32 {
		return nil, errors.New("data key must be exactly 32 bytes")
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, dataKey, nil, []byte("gatekeeper/"+purpose+"-encryption/v1")), key); err != nil {
		return nil, fmt.Errorf("derive %s encryption key: %w", purpose, err)
	}
	return key, nil
}

// encrypts and decrypts data using AES-256-GCM with a given key and associated data
func encryptWithKey(plaintext, key, associatedData []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("encryption key must be exactly 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return append(nonce, aead.Seal(nil, nonce, plaintext, associatedData)...), nil
}

// decrypts data using AES-256-GCM with a given key and associated data
func decryptWithKey(ciphertext, key, associatedData []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("encryption key must be exactly 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aead.NonceSize()+aead.Overhead() {
		return nil, errors.New("encrypted value is truncated")
	}
	nonce, body := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]
	return aead.Open(nil, nonce, body, associatedData)
}
