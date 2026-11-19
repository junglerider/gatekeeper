// package main bootstraps, starts and stops the gatekeeper service
package main

import (
	"fmt"
	"junglerider/gatekeeper/app"
	"junglerider/gatekeeper/auth"
	"junglerider/gatekeeper/client"
	clientpb "junglerider/gatekeeper/client/pb"
	"junglerider/gatekeeper/middleware"
	"junglerider/gatekeeper/user"
	userpb "junglerider/gatekeeper/user/pb"
	"net"
	"os"

	"github.com/jmoiron/sqlx"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
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
	clientController := client.NewController(clientRepo, container.Config)
	userController := user.NewController(userRepo, container.Config)
	container.Controllers = []app.Controller{
		clientController,
		userController,
		auth.NewController(container.Config),
	}
	container.Protect = middleware.Authorizer(auth.VerifyAccess(container.Config), app.BootstrapRealm)
	handler := app.RegisterRoutes(container)
	grpcListener, err := net.Listen("tcp", fmt.Sprintf(":%d", container.Config.Server.GRPCPort))
	if err != nil {
		log.Fatal().Err(err).Msg("cannot listen on gRPC port")
	}
	grpcServer := grpc.NewServer()
	clientpb.RegisterAuthServiceServer(grpcServer, client.NewGRPCAuthServer(clientController))
	userpb.RegisterAuthServiceServer(grpcServer, user.NewGRPCAuthServer(userController))
	go func() {
		if err := grpcServer.Serve(grpcListener); err != nil && err != grpc.ErrServerStopped {
			log.Fatal().Err(err).Msg("gRPC server failed")
		}
	}()
	app.Start(handler, container.Config)
	grpcServer.GracefulStop()
	if err := container.DB.Close(); err != nil {
		log.Warn().Err(err).Msg("failed to close database connection")
	}
	log.Info().Msg("gatekeeper service stopped")
}
