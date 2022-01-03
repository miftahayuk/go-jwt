package main

import (
	"time"
	"enigmacamp.com/go-jwt/authenticator"
	mdw "enigmacamp.com/go-jwt/middleware"
	"enigmacamp.com/go-jwt/model"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)





func main() {
	r := gin.Default()
	tokenConfig := authenticator.TokenConfig{
		ApplicationName: "ENIGMA",
		JwtSigningMethod: jwt.SigningMethodHS256,
		JwtSignatureKey: "P@ssw0rd",
		AccessTokenLifeTime: 30 *time.Second,
	}
	tokenService := authenticator.NewTokenService(tokenConfig)
	r.Use(mdw.NewTokenValidator(tokenService).RequireToken())

	publicRoute := r.Group("/enigma") //ini group root gitu

	publicRoute.POST("/auth", func(c *gin.Context) {
		var user model.Credential

		if err := c.BindJSON(&user); err != nil {
			c.JSON(400, gin.H{
				"message": "can't bind struct",
			})
			return
		}

		if user.Username == "enigma" && user.Password == "123" {

			token, err := tokenService.CreateAccessToken(&user)
			if err != nil {
				c.AbortWithStatus(401)
			}
			c.JSON(200, gin.H{
				"token": token,
			})
		} else {
			c.AbortWithStatus(401)
		}
	})

	publicRoute.GET("/user", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "user",
		})
	})

	err := r.Run("localhost:8888")
	if err != nil {
		panic(err)
	}
}

