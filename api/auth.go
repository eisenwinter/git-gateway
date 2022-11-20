package api

import (
	"context"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc"
	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/netlify/git-gateway/conf"
	"github.com/sirupsen/logrus"
)

type KeyFuncResolver func(context.Context) (jwt.Keyfunc, error)

func NewKeyFuncResolver(config *conf.JWTConfiguration) KeyFuncResolver {
	if strings.HasPrefix(config.SigningMethod, "RS") {
		return func(ctx context.Context) (jwt.Keyfunc, error) {
			options := keyfunc.Options{
				Ctx: ctx,
				RefreshErrorHandler: func(err error) {
					log.Printf("There was an error with the jwt.Keyfunc\nError: %s", err.Error())
				},
				RefreshInterval:   time.Hour,
				RefreshRateLimit:  time.Minute * 5,
				RefreshTimeout:    time.Second * 10,
				RefreshUnknownKID: false,
			}
			jwks, err := keyfunc.Get(config.JWKs, options)
			if err != nil {
				return nil, err
			}
			return jwks.Keyfunc, nil
		}
	}
	return func(context.Context) (jwt.Keyfunc, error) {
		return func(token *jwt.Token) (interface{}, error) {
			return []byte(config.Secret), nil
		}, nil
	}
}

// requireAuthentication checks incoming requests for tokens presented using the Authorization header
func (a *API) requireAuthentication(w http.ResponseWriter, r *http.Request) (context.Context, error) {
	logrus.Info("Getting auth token")
	token, err := a.extractBearerToken(w, r)
	if err != nil {
		return nil, err
	}

	logrus.Infof("Parsing JWT claims: %v", token)
	return a.parseJWTClaims(token, r)
}

func (a *API) extractBearerToken(w http.ResponseWriter, r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", unauthorizedError("This endpoint requires a Bearer token")
	}

	matches := bearerRegexp.FindStringSubmatch(authHeader)
	if len(matches) != 2 {
		return "", unauthorizedError("This endpoint requires a Bearer token")
	}

	return matches[1], nil
}

func (a *API) parseJWTClaims(bearer string, r *http.Request) (context.Context, error) {
	kf, err := a.keyFx(r.Context())
	if err != nil {
		return nil, unauthorizedError("Unable to validate: %v", err)
	}
	p := jwt.Parser{ValidMethods: []string{a.signingMethod}}
	claims := &GatewayClaims{}
	token, err := p.ParseWithClaims(bearer, claims, kf)
	if err != nil {
		return nil, unauthorizedError("Invalid token: %v", err)
	}
	if claims.ClientID != a.clientID {
		return nil, unauthorizedError("Invalid client id: %s", claims.ClientID)
	}
	return withToken(r.Context(), token), nil
}
