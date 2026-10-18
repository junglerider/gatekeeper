// package main bootstraps, starts and stops the gatekeeper service
package main

import (
	"fmt"
	"junglerider/gatekeeper/app"
	"junglerider/gatekeeper/auth"
	"junglerider/gatekeeper/client"
	"junglerider/gatekeeper/middleware"
	"junglerider/gatekeeper/user"
	"os"

	"github.com/jmoiron/sqlx"
	"github.com/rs/zerolog/log"
)

// performs dependency injection and bootstraps the application
func main() {
	bootstrap, genkeys, err := app.ParseFlags(os.Args[1:])
	if err != nil {
		os.Exit(2)
	}
	if genkeys {
		signingPrivateKey, verificationPublicKey, err := auth.GenerateEd25519KeyPair()
		if err != nil {
			log.Fatal().Err(err).Msg("failed to generate Ed25519 key pair")
		}
		fmt.Printf("signingPrivateKey: %s\nverificationPublicKey: %s\n", signingPrivateKey, verificationPublicKey)
		return
	}
	container := app.Init(sqlx.Connect)
	masterKey, err := auth.ParseMasterKey(container.Config.MasterKey)
	if err != nil {
		log.Fatal().Err(err).Msg("invalid APP_MASTER_KEY")
	}
	userRepo := user.NewRepo(container.DB, container.Config.DB.Database, masterKey)
	if bootstrap {
		code := app.RunBootstrap(app.Schema{DB: container.DB, Driver: container.Config.DB.Driver}, user.AdminStore{Repo: userRepo}, container.Config, os.Stdout, os.Stderr)
		_ = container.DB.Close()
		os.Exit(code)
	}
	clientRepo := client.NewRepo(container.DB, container.Config.DB.Database, masterKey)
	container.Controllers = []app.Controller{
		client.NewController(clientRepo, container.Config),
		user.NewController(userRepo, container.Config),
		auth.NewController(container.Config),
	}
	container.Protect = middleware.Authorizer(auth.VerifyAccess(container.Config))
	handler := app.RegisterRoutes(container)
	app.Start(handler, container.Config)
	if err := container.DB.Close(); err != nil {
		log.Warn().Err(err).Msg("failed to close database connection")
	}
	log.Info().Msg("gatekeeper service stopped")
}
