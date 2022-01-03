package authenticator

import (
	"fmt"
	"time"

	"enigmacamp.com/go-jwt/model"
	"github.com/golang-jwt/jwt"
)

type Token interface {
	CreateAccessToken(cred *model.Credential) (string, error)
	VerifyAccessToken(tokenString string) (jwt.MapClaims, error)
}

type token struct {
	Config TokenConfig
}

type TokenConfig struct {
	ApplicationName     string
	JwtSignatureKey     string
	JwtSigningMethod    *jwt.SigningMethodHMAC
	AccessTokenLifeTime time.Duration
}

func NewTokenService(config TokenConfig) Token {
	return &token{
		Config: config,
	}
}

func (t *token) CreateAccessToken(cred *model.Credential) (string, error) {
	now := time.Now().UTC()
	end := now.Add(t.Config.AccessTokenLifeTime)
	claims := MyClaims{
		StandardClaims: jwt.StandardClaims{
			Issuer: t.Config.ApplicationName,
		},
		Username: cred.Username,
		Email:    cred.Email,
	}
	claims.IssuedAt = now.Unix()
	claims.ExpiresAt = end.Unix()

	token := jwt.NewWithClaims(t.Config.JwtSigningMethod, claims)
	return token.SignedString([]byte(t.Config.JwtSignatureKey))

}

func (t *token) VerifyAccessToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if method, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Signing method invalid")
		} else if method != t.Config.JwtSigningMethod{
			return nil, fmt.Errorf("Signing method invalid")
		}
		return []byte(t.Config.JwtSignatureKey), nil
	})

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, err
	}
	return claims, nil
}
