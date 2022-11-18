package api

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"syscall"
	"time"

	"github.com/go-chi/cors"
	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/netlify/git-gateway/conf"
	"github.com/sebest/xff"
	"github.com/sirupsen/logrus"
)

const (
	audHeaderName  = "X-JWT-AUD"
	defaultVersion = "unknown version"
)

var bearerRegexp = regexp.MustCompile(`^(?:B|b)earer (\S+$)`)

// API is the main REST API
type API struct {
	handler       http.Handler
	config        *conf.GlobalConfiguration
	version       string
	keyFx         KeyFuncResolver
	signingMethod string
	clientID      string
}

type GatewayClaims struct {
	jwt.RegisteredClaims
	Email    string   `json:"email"`
	ClientID string   `json:"client_id"`
	Scope    string   `json:"scope"`
	Roles    []string `json:"roles"`
}

// ListenAndServe starts the REST API
func (a *API) ListenAndServe(hostAndPort string) {
	log := logrus.WithField("component", "api")

	server := &http.Server{
		Addr:    hostAndPort,
		Handler: a.handler,
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		waitForTermination(log, done)
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		server.Shutdown(ctx)
	}()

	if err := server.ListenAndServe(); err != nil {
		log.WithError(err).Fatal("API server failed")
	}
}

// waitForShutdown blocks until the system signals termination or done has a value
func waitForTermination(log logrus.FieldLogger, done <-chan struct{}) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	select {
	case sig := <-signals:
		log.Infof("Triggering shutdown from signal %s", sig)
	case <-done:
		log.Infof("Shutting down...")
	}
}

// NewAPIWithVersion creates a new REST API using the specified version
func NewAPIWithVersion(ctx context.Context, globalConfig *conf.GlobalConfiguration, version string, keyFuncResolver KeyFuncResolver, signingMethod string, clientID string) *API {
	api := &API{config: globalConfig, version: version, keyFx: keyFuncResolver, signingMethod: signingMethod, clientID: clientID}

	xffmw, _ := xff.Default()

	r := newRouter()
	r.UseBypass(xffmw.Handler)
	r.Use(addRequestID)
	r.UseBypass(newStructuredLogger(logrus.StandardLogger()))
	r.Use(recoverer)

	r.UseBypass(cors.Handler(cors.Options{
		AllowedMethods:   []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch},
		AllowedHeaders:   []string{"Accept", "Authorization", "Private-Token", "Content-Type", audHeaderName},
		AllowCredentials: true,
		MaxAge:           86400,
	}))

	r.Get("/health", api.HealthCheck)

	r.Route("/", func(r *router) {
		r.With(api.requireAuthentication).Mount("/github", NewGitHubGateway())
		r.With(api.requireAuthentication).Mount("/gitlab", NewGitLabGateway())
		r.With(api.requireAuthentication).Mount("/bitbucket", NewBitBucketGateway())
		r.With(api.requireAuthentication).Get("/settings", api.Settings)
	})
	api.handler = r
	return api
}

func (a *API) HealthCheck(w http.ResponseWriter, r *http.Request) error {
	return sendJSON(w, http.StatusOK, map[string]string{
		"version":     a.version,
		"name":        "git-gateway",
		"description": "git-gateway is a user registration and authentication API",
	})
}

func WithInstanceConfig(ctx context.Context, config *conf.Configuration, instanceID string) (context.Context, error) {
	ctx = withConfig(ctx, config)
	ctx = withInstanceID(ctx, instanceID)

	return ctx, nil
}
