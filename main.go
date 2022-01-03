package main

import (
	"fmt"
	// "go/token"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

var ApplicationName = "ENIGMA"
var JwtSigningMethod = jwt.SigningMethodHS256
var JwtSignatureKey = []byte("p@ssw0rd")

type MyClaims struct {
	jwt.StandardClaims
	Username string `json:"Username"`
	Email    string `json:"Email"`
}

type Credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type authheader struct {
	AuthorizationHeader string `header:"Authorization"`
}

func main() {
	r := gin.Default()
	r.Use(AuthtokenMiddleware())

	publicRoute := r.Group("/enigma") //ini group root gitu

	publicRoute.POST("/auth", func(c *gin.Context) {
		var user Credential

		if err := c.BindJSON(&user); err != nil {
			c.JSON(400, gin.H{
				"message": "can't bind struct",
			})
			return
		}

		if user.Username == "enigma" && user.Password == "123" {

			token, err := GenerateToken(user.Username, "user@corp")
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
	// r.GET("/customer", func(c *gin.Context) {
	// 	h := authheader{}

	// 	if err := c.ShouldBindHeader(&h); err != nil {
	// 		c.JSON(401, gin.H{
	// 			"message": "Unauthorized",
	// 		})
	// 		return
	// 	}

	// 	if h.AuthorizationHeader == "123" {
	// 		c.JSON(200, gin.H{
	// 			"message": "customer",
	// 		})
	// 		return
	// 	}
	// 	c.JSON(401, gin.H{
	// 		"message": "Unauthorized",
	// 	})
	// })

	// r.GET("/product", func(c *gin.Context) {
	// 	h := authheader{}

	// 	if err := c.ShouldBindHeader(&h); err != nil {
	// 		c.JSON(401, gin.H{
	// 			"message": "Unauthorized",
	// 		})
	// 		return
	// 	}

	// 	if h.AuthorizationHeader == "123" {
	// 		c.JSON(200, gin.H{
	// 			"message": "product",
	// 		})
	// 		return
	// 	}
	// 	c.JSON(401, gin.H{
	// 		"message": "Unauthorized",
	// 	})
	// })

	err := r.Run("localhost:8888")
	if err != nil {
		panic(err)
	}
}

//func middleware
func AuthtokenMiddleware() gin.HandlerFunc {
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
			token, err := parseToken(tokenString)
			if err != nil {
				c.JSON(500, gin.H{
					"message": "Internal server error",
				})
				c.Abort()
				return
			}
			fmt.Println(token)

			if token["iss"] == ApplicationName {
				c.Next()
			} else {
				c.JSON(401, gin.H{
					"message": "Unauthorized",
				})
				c.Abort()
				return
			}
			// if h.AuthorizationHeader == "123" {
			// 	c.Next()
			// } else {
			// 	c.JSON(401, gin.H{
			// 		"message": "Unauthorized",
			// 	})
			// 	c.Abort()
			// }
		}
	}
}

func parseToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if method, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Signing method invalid")
		} else if method != JwtSigningMethod {
			return nil, fmt.Errorf("Signing method invalid")
		}
		return JwtSignatureKey, nil
	})

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, err
	}
	return claims, nil
}

//fungsi generate token
func GenerateToken(userName, email string) (string, error) {
	claims := MyClaims{
		StandardClaims: jwt.StandardClaims{
			Issuer:   ApplicationName,
			IssuedAt: time.Now().Unix(), //bisa beda2 gitu tokennya tiap di generate
		},
		Username: userName,
		Email:    email,
	}

	token := jwt.NewWithClaims(JwtSigningMethod, claims)

	return token.SignedString(JwtSignatureKey)
}
