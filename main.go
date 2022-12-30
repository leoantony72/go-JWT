package main

import (
	"errors"
	"fmt"
	"net/http"

	// "fmt"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

type User struct {
	ID           string
	Name         string `json:"name"`
	Password     string `json:"password"`
	refreshToken string
}

var user1 = User{ID: "1", Name: "leo", Password: "test"}
var secret string = "nice-secret1231sfafawagrhr"

func main() {
	r := gin.Default()

	public := r.Group("/api")
	public.GET("/", home)
	public.POST("/login", login)
	public.POST("/logout", Validate(), Logout)

	protected := r.Group("/api/admin")
	protected.Use(Validate())
	protected.GET("/", adminHome)

	r.Run(":8080")
}

func home(c *gin.Context) {
	c.JSON(200, gin.H{"msg": "all good"})
}
func adminHome(c *gin.Context) {
	c.JSON(200, gin.H{"msg": "admin, all good"})
}

func login(c *gin.Context) {
	u := User{}
	err := c.BindJSON(&u)
	if err != nil {
		c.AbortWithError(400, err)
		panic(err)
	}
	u.ID = "1"

	if u.Name != user1.Name && u.Password != user1.Password {
		c.JSON(400, gin.H{"msg": "Password incorrect"})
	}

	//give user jwt token &
	token, err := GenerateAccessToken(u.Name, u.ID)
	if err != nil {
		c.JSON(400, gin.H{"msg": err.Error()})

		return
	}
	refreshToken, err := GenerateRefreshToken(u.Name, u.ID)
	if err != nil {
		c.JSON(400, gin.H{"msg": err.Error()})

		return
	}
	//refresh token
	user1.refreshToken = refreshToken
	fmt.Printf("user1: %v\n", user1.refreshToken)

	c.SetCookie("access-Token", token, 3600, "/", "", false, true)
	c.SetCookie("refresh-Token", refreshToken, 3600, "/", "", false, true)
	c.JSON(200, gin.H{"msg": "success"})
}

func GenerateAccessToken(name string, Id string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"name": name,
		"ID":   Id,
		"exp":  time.Now().Add(30 * time.Second).Unix(),
	})

	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", errors.New("failed to create Token")
	}
	return tokenString, nil
}

func GenerateRefreshToken(name string, Id string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"name": name,
		"ID":   Id,
		"exp":  time.Now().Add(time.Hour * 24 * 30).Unix(),
	})

	refreshTokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", errors.New("failed to create Token")
	}
	return refreshTokenString, nil
}

func JWTvalidate(tokenString string) (*jwt.Token, jwt.MapClaims, error) {
	//decode/validate
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexepcted signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		return token, claims, nil
	}
	return nil, nil, err
}
func refreshTokenValidation(refreshToken string) error {
	result := refreshToken == user1.refreshToken
	if !result {
		return errors.New("refresh token not valid")
	}
	return nil
}

func Validate() gin.HandlerFunc {
	return func(c *gin.Context) {
		//Get the cookie
		tokenString, err := c.Cookie("access-Token")
		CheckErr(err)
		_, claims, err := JWTvalidate(tokenString)
		if err != nil {
			if err.Error() == "Token is expired" {
				refreshToken, err := c.Cookie("refresh-Token")
				if err != nil {
					c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"msg": "Please Login"})
					return
				}
				claims, err := validateRefreshToken(refreshToken)
				CheckErr(err)
				user := claims["name"].(string)
				id := claims["ID"].(string)
				accessToken, err := GenerateAccessToken(user, id)
				if err != nil {
					c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"msg": "Something went wrong"})
				}

				c.SetCookie("access-Token", accessToken, 3600, "/", "", false, true)
				fmt.Printf("Access-Token updated, New Token🥙: %v\n", accessToken)
				c.Next()

			} else {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"msg": "Invalid Token"})
			}
		}
		c.Set("name", claims["name"])

		c.Next()
	}

}

func Logout(c *gin.Context) {
	user1.refreshToken = ""
	c.SetCookie("access-Token", "token", -1, "/", "", false, true)
	c.SetCookie("refresh-Token", "refreshToken", -1, "/", "", false, true)

	c.JSON(200,gin.H{"msg":"Logout Success"})
}
func validateRefreshToken(refreshToken string) (jwt.MapClaims, error) {
	err := refreshTokenValidation(refreshToken)
	CheckErr(err)
	_, claims, err := JWTvalidate(refreshToken)
	CheckErr(err)

	return claims, err

}
func CheckErr(err error) {
	var c *gin.Context

	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, (err.Error()))
	}
}

/*
// Check if the user have refresh-token
				// validate the refresh token of the user and also check the db
				// validate the JWT
				// Generate new access-Token
				// Send to the client
				refreshTokenString, err := c.Cookie("refresh-Token")
				if err != nil {
					c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"msg": "Login Again"})
				} else {
					//check if the token is of the user
					//if not present return error
					err = refreshTokenValidation(refreshTokenString)
					if err != nil {
						c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"msg": err.Error()})
					} else {
						//Validates the jwt which also checks the exp date
						_, claims, err := JWTvalidate(refreshTokenString)
						if err != nil {
							if err.Error() == "Token is expired" {
								c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"msg": "Login Again"})
							}
						} else {
							//Generate new access-Token
							user := claims["user"].(string)
							id := claims["id"].(string)
							accessToken, err := GenerateAccessToken(user, id)
							if err != nil {
								c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"msg": "Something went wrong"})
							}

							c.SetCookie("access-Token", accessToken, 3600, "/", "", false, true)
							c.Next()
						}

					}
				}
*/
