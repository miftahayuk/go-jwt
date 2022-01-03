package middleware

import (
	"strings"

	"enigmacamp.com/go-jwt/authenticator"
	"github.com/gin-gonic/gin"
)

type authheader struct {
	AuthorizationHeader string `header:"Authorization"`
}

type AuthTokenMiddleware struct{
	accToken authenticator.Token
}

func NewTokenValidator(accToken authenticator.Token) *AuthTokenMiddleware{
	return &AuthTokenMiddleware{
		accToken: accToken,
	}
}

func (a *AuthTokenMiddleware)RequireToken()gin.HandlerFunc{
	return func(c *gin.Context) {
		if c.Request.URL.Path == "/enigma/auth" {
			c.Next() //ini nnti masuk r post login di main
		} else {
			h := authheader{}

			if err := c.ShouldBindHeader(&h); err != nil {
				c.JSON(401, gin.H{
					"message": "Unauthorized",
				})
				c.Abort()
			}

			tokenString := strings.Replace(h.AuthorizationHeader, "Bearer ", "", -1)

			if tokenString == "" {
				c.JSON(401, gin.H{
					"message": "Unauthorized",
				})
				c.Abort()
				return
			}
			// fmt.Println("Token string",tokenString)
			token, err := a.accToken.VerifyAccessToken(tokenString)
			if err != nil {
				c.JSON(401, gin.H{
					"message": "Unauthorized",
				})
				c.Abort()
				return
			}
			if token !=nil{
				c.Next()
			}else{
				c.AbortWithStatusJSON(401,gin.H{"message":"Unauthorized"})
				return
			}
		}
	}
}

