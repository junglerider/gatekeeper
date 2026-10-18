// datamodel package embeds the database table definitions
package datamodel

import _ "embed"

//go:embed mysql/clients.sql
var ClientsSQL string

//go:embed mysql/users.sql
var UsersSQL string

//go:embed postgres/clients.sql
var PostgresClientsSQL string

//go:embed postgres/users.sql
var PostgresUsersSQL string
