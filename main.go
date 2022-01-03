package main

import (
	"net/http"
	"time"

	"enigmacamp.com/go-jwt/authenticator"
	mdw "enigmacamp.com/go-jwt/middleware"
	"enigmacamp.com/go-jwt/model"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt"
)

func main() {
	r := gin.Default()
	client := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB: 0,
	})


	tokenConfig := authenticator.TokenConfig{
		ApplicationName: "ENIGMA",
		JwtSigningMethod: jwt.SigningMethodHS256,
		JwtSignatureKey: "P@ssw0rd",
		AccessTokenLifeTime: 60 *time.Second,
		Client: client,
	}
	tokenService := authenticator.NewTokenService(tokenConfig)
	r.Use(mdw.NewTokenValidator(tokenService).RequireToken())

	publicRoute := r.Group("/enigma") //ini group root gitu

	publicRoute.POST("/auth", func(c *gin.Context) {
		var user model.Credential

		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "can't bind struct",
			})
			return
		}

		if user.Username == "enigma" && user.Password == "123" {

			token, err := tokenService.CreateAccessToken(&user)
			if err != nil {
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			err = tokenService.StoreAccessToken(user.Username,token)
			if err != nil{
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			c.JSON(http.StatusOK,gin.H{
				"token": token,
			})
		} else {
			c.AbortWithStatus(401)
		}
	})

	publicRoute.GET("/user", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": c.GetString("username"),
		})
	})

	err := r.Run("localhost:8888")
	if err != nil {
		panic(err)
	}
}

