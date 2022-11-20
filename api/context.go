package api

import (
	"context"
	"net/url"

	jwt "github.com/golang-jwt/jwt/v4"
)

type Role struct {
	Name string
}

type contextKey string

func (c contextKey) String() string {
	return "git-gateway api context key " + string(c)
}

const (
	accessTokenKey = contextKey("access_token")
	tokenKey       = contextKey("jwt")
	requestIDKey   = contextKey("request_id")
	configKey      = contextKey("config")
	instanceIDKey  = contextKey("instance_id")
	instanceKey    = contextKey("instance")
	proxyTargetKey = contextKey("target")
	signatureKey   = contextKey("signature")
	netlifyIDKey   = contextKey("netlify_id")
)

// withToken adds the JWT token to the context.
func withToken(ctx context.Context, token *jwt.Token) context.Context {
	return context.WithValue(ctx, tokenKey, token)
}

// getToken reads the JWT token from the context.
func getToken(ctx context.Context) *jwt.Token {
	obj := ctx.Value(tokenKey)
	if obj == nil {
		return nil
	}

	return obj.(*jwt.Token)
}

func getClaims(ctx context.Context) *GatewayClaims {
	token := getToken(ctx)
	if token == nil {
		return nil
	}
	return token.Claims.(*GatewayClaims)
}

func withRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

func getRequestID(ctx context.Context) string {
	obj := ctx.Value(requestIDKey)
	if obj == nil {
		return ""
	}

	return obj.(string)
}

func withProxyTarget(ctx context.Context, target *url.URL) context.Context {
	return context.WithValue(ctx, proxyTargetKey, target)
}

func getProxyTarget(ctx context.Context) *url.URL {
	obj := ctx.Value(proxyTargetKey)
	if obj == nil {
		return nil
	}
	return obj.(*url.URL)
}

func withAccessToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, accessTokenKey, token)
}

func getAccessToken(ctx context.Context) string {
	obj := ctx.Value(accessTokenKey)
	if obj == nil {
		return ""
	}
	return obj.(string)
}
