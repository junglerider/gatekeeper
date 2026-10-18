# gatekeeper

Microservice for identity and access management.

- [OpenAPI documentation](./openapi.yaml)
- [REST API Examples](./rest.http)


## What it does

Gatekeeper is a lightweight multi-tenant IAM service enabling a JSON Web Token (JWT) workflow for authentication and authorization. It provides open login, auth, and refresh endpoints to other applications.

Gatekeeper also provides protected endpoints to manage client and user accounts. It can create, read, update, and delete accounts via a REST API. Updates enable password changes, locking and unlocking, and RBAC/ACL configuration. These endpoints are for internal use and should not be exposed.

### Features

- standards-compliant JWT authentication
- supports two-factor authentication with OTP
- supports authentication via API key
- generates OTP QR code and URI
- EdDSA (Ed25519) asymmetric key signing
- minimal and flexible
- secure storage
- works with either MySQL or PostgreSQL RDBMS
- fits microservice architecture

## What it does not

Gatekeeper is designed as a pluggable core service for different use cases. As such, it is minimal and flexible. The caller is responsible for:

- providing a UI
- enforcing password policies
- creating/managing audit logs
- key rotation
- rate limiting

### Client and user accounts

Client accounts have two functions. They can be used directly by tenants for accessing a system machine-to-machine. They can also be used to group user accounts under a specific client. A client account can optionally be authenticated via API key.

User accounts are intended to grant people access to a system. Unlike client accounts, user accounts support two-factor authentication via TOTP and an authenticator application.

### Realms

Gatekeeper is designed to recognise different realms. A realm represents an application domain. Realms are isolated from each other and contain their own accounts and JWT secrets, which means credentials and tokens from different realms cannot be used interchangeably. Arbitrary realms can be configured for your needs. If you don't require realms, it is safe to ignore them. Gatekeeper then falls back to the default `api` realm.

When creating a client or user account, include the optional `realm` in the JSON request body; it defaults to `api`. Account updates use `PATCH` because they accept partial JSON objects. `/livez` checks that the service process is running, while `/readyz` checks database connectivity and returns `503 Service Unavailable` when the database cannot be reached.

## Installation and bootstrapping

```sh
# 1. generate a master encryption key
openssl rand -base64 32

# 2. generate a Ed25519 signing key pair
./gatekeeper --genkeys

# 3. edit config.yaml and environment variables
vim config.yaml

# 4. generate database tables
./gatekeeper --bootstrap
```

- Compile Gatekeeper or download the binary
- Edit the config.yaml file in the same directory
- Configure the database settings
- Run "gatekeeper --genkeys" to print a base64 Ed25519 signing seed and its matching public key
- Inject keys and secrets as environment variables or create an .env file for local deployment
- Run "gatekeeper --bootstrap" to create the required database tables and insert an admin user
- Alternatively, create the tables in `datamodel` manually and then run "gatekeeper --bootstrap"
- Run the program without any arguments as a server
- Login as admin/admin and change the admin's password

## JWT authentication workflow

- send a `POST /clients/login` or `POST /users/login` request with valid credentials and obtain the access token and refresh token in the response
- store these tokens in your session for subsequent use
- send the access token to `POST /clients/auth` or `POST /users/auth` to verify and decode it for subsequent API access
- when the access token expires, request a new one by sending `POST /clients/refresh` or `POST /users/refresh` with the refresh token instead of the login credentials in the request body
- the response contains a new access token and a new refresh token
- store these tokens in your session for subsequent use
- to end a session, send `POST /clients/logout` or `POST /users/logout` with the refresh token in the request body
- when an access or a refresh token expires or when the session expires, you receive a 401 Unauthorized response from the authentication endpoint

### Two-factor authentication

User authentication can optionally provide a two-factor authentication (2FA) workflow with time-based one-time (TOTP) passwords. These passwords are compatible with popular authenticator applications, such as those from Google, Microsoft, or Okta. To enable 2FA, follow these steps:

- generate a random 32-byte secret string
- store this secret in the `otpSecret` property of a user account and set the `otpEnabled` property to `true`
- the secret is automatically encrypted by Gatekeeper
- every user with `otpEnabled` should be provisioned with a different OTP secret
- display the secret to the user and let them add it to a TOTP authenticator application
- perform a regular user login with the user's password and store the returned challenge token
- obtain the OTP from the user and send it along with the challenge token to `POST /users/otp/login?realm=:realm`
- upon successful authentication, the OTP login endpoint returns the regular access and refresh token pair
- 2FA is not supported for client accounts

### Authentication with API key

For selected and trusted clients, Gatekeeper can authenticate requests using an API key instead of a JWT token. API keys are stored securely in the database and are sent to `POST /clients/auth` for verification without a login. This method is less secure than JWT tokens and should only be used in conjunction with TLS and IP whitelisting. API keys are realm-specific.

API key authentication uses a TTL cache to prevent it from accessing the database every time. Only the `client_id`, `access` and configured static keys are returned.

### JWT best practice

Choose a brief time to live (TTL) for access tokens, for example 5-15 minutes. A 5 minute access token TTL means that authentication will not hit the database for 5 minutes and an attacker who obtains the token can use it only for 5 minutes. Choose a refresh token TTL that equals the maximum allowed session idle time, for example 15-60 minutes. An attacker who obtains the refresh token can initiate further token refreshes. Therefore, also limit the maximum session lifetime to a reasonable value.

### JWT claims

The following claims are returned by the `POST /clients/auth` and `POST /users/auth` endpoints:

| name | meaning | description |
|---|---|---|
| iat | issued at | token issue timestamp |
| exp | expiry | token expiry timestamp |
| sub | subject | user's name |
| jti | JWT token id | token UUID |
| sid | session id | session UUID |
| sex | session expiry | session expiry timestamp |
| client_id | client id | client identifier |
| access | RBAC/ACL | JSON object with roles and permissions |

The `typ` value is set in the JOSE header (`typ: at+jwt`, `rt+jwt`, or `challenge+jwt`) and is verified during token validation. Realm-specific `iss` and `aud` claims are also enforced when configured so tokens cannot be replayed across issuer or audience boundaries.


### Authorization

The `POST /clients/auth` or `POST /users/auth` endpoints perform JWT token verification and return a decoded list of claims in JSON format. These claims contain, among others, the `client_id` and `access` claims. For user accounts, the `sub` claim contains the user's name. The `access` claim is a free-form JSON object. You can use this JSON object to encode access roles and/or privileges according to your needs.

The `access` JSON object is stored in encrypted form in the database.

## Gatekeeper configuration

Application configuration is provided in the `config.yml` file. The secrets in this configuration file should not be stored directly in the YAML itself. Inject the secrets via environment variables, for example `DB_PASSWORD` for the database password. For development and testing, you can provide the secrets in a local `.env` file. The `.env` file should be git-ignored and never committed to the repository.

### Database configuration

Set `db.driver` to `mysql` or `postgres`. If omitted, it defaults to `mysql`. The `db.database` value names the database to connect to; PostgreSQL tables are created in the connection's default schema (normally `public`).

Database TLS is disabled by default. To enable TLS, set `db.tls.enabled: true`. The server certificate is verified against system roots unless `db.tls.caCert` names a PEM CA certificate file. PostgreSQL connections use `verify-full`, including hostname verification. `db.tls.skipVerify` defaults to `false`; setting it to `true` keeps TLS encryption but skips server certificate verification for both database drivers. This makes the connection vulnerable to man-in-the-middle attacks and should only be used when that risk is explicitly acceptable. `skipVerify` requires `enabled: true`; when enabled, `caCert` is not used.

For PostgreSQL, change the driver and port, and optionally provide a CA certificate:

```yaml
db:
  driver: postgres
  host: localhost
  user: ${DB_USER}
  password: ${DB_PASSWORD}
  port: 5432
  database: gatekeeper
  tls:
    enabled: true
    skipVerify: false
    caCert: ${DB_TLS_CA_CERT}
```

### Secrets and keys

Passwords and API keys are hashed securely. Access data and OTP secrets are encrypted with a random per-account data encryption key. This key is wrapped using the master key supplied through `MASTER_KEY`. The master key must be a base64-encoded 32-byte string. Keep it in your deployment secret store. Losing or changing the master key without rewrapping the stored account keys will make encrypted access data and OTP secrets unavailable.

JWT signing keys are configured per realm as an Ed25519 key pair. `signingPrivateKey` is the base64-encoded 32-byte Ed25519 seed and must be kept secret. `verificationPublicKey` is the base64-encoded 32-byte public key and can be distributed to token consumers. Use `gatekeeper --genkeys` to generate unique new signing key pairs.

Do not enable `trace` logging on production, as it logs sensitive information. Set the logging level to `info` or `debug` at most.

### Realm configuration

There are two preconfigured application domains: `api` which is the default, and `internal` which is used for accessing gatekeeper. You may add more realms as needed.

| name | description | example |
|---|---|---|
| realm.signingPrivateKey | base64-encoded 32-byte Ed25519 seed used to sign JWTs; keep secret | key |
| realm.verificationPublicKey | base64-encoded 32-byte Ed25519 public key used to verify JWTs | key |
| realm.accessTokenLifetime | lifetime of access token in seconds | 300 |
| realm.refreshTokenLifetime | lifetime of refresh token in seconds | 1800 |
| realm.claims | static claims to add to JWT | see below  |
| realm.claims.aud | static audience claim for this realm | 'My application' |
| realm.claims.iss | static issuer claim for this realm | 'https://my-api.com' |
