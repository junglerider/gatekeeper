package user

import (
	"database/sql"
	"errors"

	"junglerider/gatekeeper/utils"
)

// adapts a user repository to the app.AdminStore interface
type AdminStore struct {
	Repo UserRepo
}

func (s AdminStore) AdminExists(realm, clientID, name string) (bool, error) {
	_, err := s.Repo.ReadUser(&UserPK{Realm: realm, ClientID: clientID, Name: name})
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func (s AdminStore) CreateAdmin(realm, clientID, name, password string, access any) error {
	accessJSON, err := utils.JSONToStr(&access)
	if err != nil {
		return err
	}
	isActive, otpEnabled := true, false
	return s.Repo.CreateUser(User{
		ClientID:   clientID,
		Realm:      realm,
		Name:       name,
		Password:   &password,
		Access:     accessJSON,
		AccessData: &access,
		IsActive:   &isActive,
		OTPEnabled: &otpEnabled,
	})
}
