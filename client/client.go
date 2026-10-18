// client package implements client account management
package client

import (
	"time"
)

// client account model
type Client struct {
	ClientID    string     `db:"client_id" json:"clientId"`
	Realm       string     `json:"realm"`
	Password    *string    `db:"password" json:"password"`
	APIKey      *string    `db:"api_key" json:"apiKey"`
	EncKey      *string    `db:"enc_key" json:"-"`
	Access      *string    `db:"access" json:"-"`
	AccessData  *any       `json:"access"`
	IsActive    *bool      `db:"is_active" json:"isActive"`
	PwdExpiry   *time.Time `db:"pwd_expiry" json:"pwdExpiry"`
	LastLogin   *int64     `db:"last_login" json:"lastLogin"`
	LastRefresh *int64     `db:"last_refresh" json:"lastRefresh"`
	JTIRefresh  *string    `db:"jti_refresh" json:"jtiRefresh"`
	CreatedAt   *time.Time `db:"created_at" json:"createdAt"`
	UpdatedAt   *time.Time `db:"updated_at" json:"updatedAt"`
}

// client implements account interface
func (s *Client) GetClientID() string { return s.ClientID }
func (s *Client) GetRealm() string    { return s.Realm }
func (s *Client) GetName() string     { return "" }
func (s *Client) GetAccess() *any     { return s.AccessData }
