// user package implements user account management
package user

import (
	"time"
)

// primary key properties of a user
type UserPK struct {
	Realm    string `db:"client_id" json:"-"`
	ClientID string `db:"client_id" json:"clientId"`
	Name     string `json:"name"`
}

// user account model
type User struct {
	ClientID    string     `db:"client_id" json:"clientId"`
	Realm       string     `json:"realm"`
	Name        string     `json:"name"`
	Password    *string    `json:"password"`
	Access      *string    `db:"access" json:"-"`
	AccessData  *any       `json:"access"`
	IsActive    *bool      `db:"is_active" json:"isActive"`
	PwdExpiry   *time.Time `db:"pwd_expiry" json:"pwdExpiry"`
	LastLogin   *int64     `db:"last_login" json:"lastLogin"`
	LastRefresh *int64     `db:"last_refresh" json:"lastRefresh"`
	JTIRefresh  *string    `db:"jti_refresh" json:"jtiRefresh"`
	OTPEnabled  *bool      `db:"otp_enabled" json:"otpEnabled"`
	OTPSecret   *string    `db:"otp_secret" json:"otpSecret"`
	EncKey      *string    `db:"enc_key" json:"-"`
	CreatedAt   *time.Time `db:"created_at" json:"createdAt"`
	UpdatedAt   *time.Time `db:"updated_at" json:"updatedAt"`
}

// user implements account interface
func (u *User) GetClientID() string { return u.ClientID }
func (u *User) GetRealm() string    { return u.Realm }
func (u *User) GetName() string     { return u.Name }
func (u *User) GetAccess() *any     { return u.AccessData }

// one-time password login structure
type OTPLogin struct {
	ChallengeToken string `json:"challengeToken"`
	ClientID       string `json:"-"`
	Name           string `json:"-"`
	OTP            string `json:"otp"`
}
