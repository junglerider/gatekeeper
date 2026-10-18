// app package implements application configuration, initialization, routing and provides base controller
package app

import (
	"context"
	"fmt"
	"junglerider/gatekeeper/middleware"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jmoiron/sqlx"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// controllers register open routes (login, token refresh...) on the public router and
// CRUD routes on the protected router, which requires administrative access
type Controller interface {
	RegisterRoutes(public chi.Router, protected chi.Router)
}

// dependency injection container
type Container struct {
	Config      *Config
	DB          *sqlx.DB
	Controllers []Controller
	// middleware guarding the protected routes, required by RegisterRoutes
	Protect func(http.Handler) http.Handler
}

type DBConnector func(driverName, dataSourceName string) (*sqlx.DB, error)

// initializes application dependencies
func Init(connector DBConnector) *Container {
	var container = &Container{}

	// initialise config
	config, err := ReadConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("cannot read config")
	}
	container.Config = config
	// log.Trace().Interface("config", config).Msg("loaded")

	// initialise logger
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	if logLevel, err := zerolog.ParseLevel(config.Server.LogLevel); err == nil {
		zerolog.SetGlobalLevel(logLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
	if config.Server.PrettyPrint {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout})
	}

	// initialise database
	container.DB, err = connectDatabase(connector, config)
	if err != nil {
		log.Fatal().Err(err).Msg("cannot open database:")
	}
	container.DB.SetConnMaxLifetime(time.Minute * 5)
	container.DB.SetMaxOpenConns(20)
	container.DB.SetMaxIdleConns(10)
	return container
}

// creates endpoint routes and register controllers
func RegisterRoutes(container *Container) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	bc := &BaseController{Config: container.Config}

	// internal health route
	r.Get("/livez", func(w http.ResponseWriter, r *http.Request) {
		bc.Reply(w, 200, []byte(`{"status": "OK"}`))
	})
	r.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if container.DB == nil {
			log.Error().Msg("database is unavailable")
			bc.StatusReply(w, http.StatusServiceUnavailable, "database is unavailable")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := container.DB.PingContext(ctx); err != nil {
			log.Error().Err(err).Msg("database readiness check failed")
			bc.StatusReply(w, http.StatusServiceUnavailable, "database is unavailable")
			return
		}
		bc.Reply(w, http.StatusOK, []byte(`{"status": "OK"}`))
	})

	if container.Protect == nil {
		panic("app: container.Protect middleware is required")
	}
	registerAll := func(public, protected chi.Router) {
		for _, controller := range container.Controllers {
			controller.RegisterRoutes(public, protected)
		}
	}
	// the public and the protected group share the same request logging
	r.Group(func(public chi.Router) {
		if container.Config.Server.LogRequests {
			public.Use(middleware.RequestLogger(container.Config.Server.PrettyPrint))
		}
		public.Group(func(protected chi.Router) {
			protected.Use(container.Protect)
			registerAll(public, protected)
		})
	})

	return r
}

// starts the HTTP server and handles graceful shutdown on syscall signals
func Start(handler http.Handler, config *Config) {

	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", config.Server.Port),
		Handler:           handler,
		ReadHeaderTimeout: 3 * time.Second,  // Time allowed to read request headers
		ReadTimeout:       15 * time.Second, // Time allowed to read the entire request body
		WriteTimeout:      15 * time.Second, // Time allowed to write the response back
		IdleTimeout:       60 * time.Second, // Time allowed to keep keep-alive connections idle
	}
	serverCtx, serverStopCtx := context.WithCancel(context.Background())

	// listen for syscall signals
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer signal.Stop(sig)

	go func() {
		signalReceived := <-sig

		// initiate shutdown with a grace period of 10 seconds
		log.Warn().Msgf("received %s, initiating shutdown...", signalReceived.String())
		shutdownCtx, shutdownCancel := context.WithTimeout(serverCtx, 10*time.Second)

		go func() {
			<-shutdownCtx.Done()
			if shutdownCtx.Err() == context.DeadlineExceeded {
				log.Warn().Msg("graceful shutdown timed out... forcing exit")
			} else {
				shutdownCancel()
			}
		}()

		// trigger graceful shutdown
		err := server.Shutdown(shutdownCtx)
		if err != nil {
			log.Fatal().Stack().Err(err)
		}
		serverStopCtx()
	}()

	// run the server
	log.Info().Msgf("gatekeeper service listening on port %d", config.Server.Port)
	err := server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		log.Fatal().Stack().Err(err)
	}

	// wait for server context to be stopped
	<-serverCtx.Done()
}
