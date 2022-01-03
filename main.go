package main

import "github.com/gin-gonic/gin"

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

	r.POST("/login", func(c *gin.Context) {
		var user Credential

		if err := c.BindJSON(&user); err != nil {
			c.JSON(400, gin.H{
				"message": "can't bind struct",
			})
			return
		}

		if user.Username == "enigma" && user.Password == "123" {
			c.JSON(200, gin.H{
				"token": "123",
			})
		} else {
			c.AbortWithStatus(401)
		}
	})

	r.GET("/customer", func(c *gin.Context) {
		h := authheader{}

		if err := c.ShouldBindHeader(&h); err != nil {
			c.JSON(401, gin.H{
				"message": "Unauthorized",
			})
			return
		}

		if h.AuthorizationHeader == "123" {
			c.JSON(200, gin.H{
				"message": "customer",
			})
			return
		}
		c.JSON(401, gin.H{
			"message": "Unauthorized",
		})
	})

	r.GET("/product", func(c *gin.Context) {
		h := authheader{}

		if err := c.ShouldBindHeader(&h); err != nil {
			c.JSON(401, gin.H{
				"message": "Unauthorized",
			})
			return
		}

		if h.AuthorizationHeader == "123" {
			c.JSON(200, gin.H{
				"message": "product",
			})
			return
		}
		c.JSON(401, gin.H{
			"message": "Unauthorized",
		})
	})

	err := r.Run("localhost:8888")
	if err != nil {
		panic(err)
	}
}

func AuthtokenMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.URL.Path == "/login" {
			c.Next()
		} else {
			h := authheader{}

			if err := c.ShouldBindHeader(&h); err != nil {
				c.JSON(401, gin.H{
					"message": "Unauthorized",
				})
				c.Abort()
			}

			if h.AuthorizationHeader == "123" {
				c.Next()
			} else {
				c.JSON(401, gin.H{
					"message": "Unauthorized",
				})
				c.Abort()
			}
		}
	}
}
