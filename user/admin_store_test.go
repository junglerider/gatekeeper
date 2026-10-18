package user

import (
	"database/sql"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAdminStore_AdminExists(t *testing.T) {
	s := AdminStore{Repo: &mockUserRepo{readUserFunc: func(u *UserPK) (*User, error) {
		assert.Equal(t, UserPK{Realm: "internal", ClientID: "c", Name: "n"}, *u)
		return &User{}, nil
	}}}
	ok, err := s.AdminExists("internal", "c", "n")
	assert.NoError(t, err)
	assert.True(t, ok)

	s = AdminStore{Repo: &mockUserRepo{readUserFunc: func(u *UserPK) (*User, error) { return nil, sql.ErrNoRows }}}
	ok, err = s.AdminExists("internal", "c", "n")
	assert.NoError(t, err)
	assert.False(t, ok)

	s = AdminStore{Repo: &mockUserRepo{readUserFunc: func(u *UserPK) (*User, error) { return nil, errors.New("db down") }}}
	_, err = s.AdminExists("internal", "c", "n")
	assert.Error(t, err)
}

func TestAdminStore_CreateAdmin(t *testing.T) {
	var created User
	s := AdminStore{Repo: &mockUserRepo{createUserFunc: func(u User) error { created = u; return nil }}}
	assert.NoError(t, s.CreateAdmin("internal", "c", "n", "pw", map[string]any{"gatekeeper": []any{"admin"}}))
	assert.Equal(t, "internal", created.Realm)
	assert.Equal(t, "c", created.ClientID)
	assert.Equal(t, "n", created.Name)
	assert.Equal(t, "pw", *created.Password)
	assert.JSONEq(t, `{"gatekeeper":["admin"]}`, *created.Access)
	assert.True(t, *created.IsActive)
	assert.False(t, *created.OTPEnabled)

	s = AdminStore{Repo: &mockUserRepo{createUserFunc: func(u User) error { return errors.New("dup") }}}
	assert.Error(t, s.CreateAdmin("internal", "c", "n", "pw", nil))
}
