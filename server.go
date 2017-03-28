package main

import (
	"log"
	"fmt"
	"net/http"
	"os"
	"time"
	"math/rand"
	"io"
	"strconv"

	"github.com/go-ozzo/ozzo-config"
	"github.com/go-ozzo/ozzo-routing"
	"github.com/go-ozzo/ozzo-routing/access"
	"github.com/go-ozzo/ozzo-routing/slash"
	"github.com/go-ozzo/ozzo-routing/content"
	"github.com/go-ozzo/ozzo-routing/fault"
	"github.com/go-ozzo/ozzo-routing/file"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-ozzo/ozzo-routing/auth"
)

type Claims struct {
	Username string `json:"username"`
	// recommended having
	jwt.StandardClaims
}

type UserProfile struct {
	Id uint32
	FirstName string
	LastName string
	Email string
}

func main() {
	port := os.Getenv("PORT")

	if port == "" {
		port = "8080"
		//log.Fatal("$PORT must be set")
	}

	// create a Config object
	c := config.New()

	// load from one or multiple JSON, YAML, or TOML files.
	// file formats are determined by their extensions: .json, .yaml, .yml, .toml
	// c.Load("app.json", "app.dev.json")

	// load configuration from a JSON string
	c.LoadJSON([]byte(`{
		"Version": "2.0",
		"Author": {
		    "Name": "Foo",
		    "Email": "bar@example.com"
		}
	    }`))

	// get the "Version" value, return "1.0" if it doesn't exist in the config
	version := c.GetString("Version", "1.0")

	//c.Set("Author.Email", "bar@example.com")

	var author struct {
		Name, Email string
	}
	// populate the author object from the "Author" configuration
	c.Configure(&author, "Author")

	fmt.Println(version)
	fmt.Println(author.Name)
	fmt.Println(author.Email)

	router := routing.New()

	router.Use(
		// all these handlers are shared by every route
		access.Logger(log.Printf),
		slash.Remover(http.StatusMovedPermanently),
		fault.Recovery(log.Printf),
	)

	// serve RESTful APIs
	api := router.Group("/api")
	api.Use(
		// these handlers are shared by the routes in the api group only
		//content.TypeNegotiator(content.JSON, content.XML),
		content.TypeNegotiator(content.JSON),
	)
	api.Get("/users", func(c *routing.Context) error {
		return c.Write("user list")
	})
	api.Post("/users", func(c *routing.Context) error {
		return c.Write("create a new user")
	})
	api.Put(`/users/<id:\d+>`, func(c *routing.Context) error {
		return c.Write("update user " + c.Param("id"))
	})
	api.Post("/auth/refresh-token-auth", func(c *routing.Context) error {
		return c.Write("")
	})
	api.Post("/auth/token-auth", func(c *routing.Context) error {
		// Create a new token object, specifying signing method and the claims
		// you would like it to contain.
		claims := Claims{
			"test",
			jwt.StandardClaims{
				Audience: "",
				ExpiresAt: time.Now().Add(time.Hour * 1).Unix(),
				//ExpiresAt: time.Now().Unix(),
				Issuer: "localhost:8080",
				Subject: "",
				Id: "",
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		// Sign and get the complete encoded token as a string using the secret
		hmacSampleSecret := []byte("asdjkh34mx0_23#@594jSrtv4")
		tokenString, err := token.SignedString(hmacSampleSecret)
		fmt.Println(err)
		return c.Write(tokenString)
	})
	api.Post("/auth/token/validate", func(c *routing.Context) error {
		tokenString := c.Request.Header.Get("Authorization")
		if tokenString == "" {
			log.Fatal("x-auth-token must be provided")
			tokenString = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJuYmYiOjE0NDQ0Nzg0MDB9.u1riaD1rW97opCoAuRCTy4w58Br-Zk-bh7vLiRIsrpU"
		}

		token, err := parseToken(tokenString)
		tokenError := validateToken(token, err)

		if tokenError.IsValid {
			return c.Write("OK")
		} else {
			return c.Write(tokenError)
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			fmt.Println(claims["foo"], claims["nbf"])
			return c.Write("OK")
		} else {
			return c.Write(err)
		}
	})
	api.Use(auth.JWT("asdjkh34mx0_23#@594jSrtv4", auth.JWTOptions{
		SigningMethod: "HS256",
	}))
	api.Get("/user/profile", func(c *routing.Context) error {
		token := c.Get("JWT").(*jwt.Token)
		if token == nil {
			log.Fatal("x-auth-token must be provided")
		}

		data := &struct{
			A string
			B bool
		}{}

		// assume the body data is: {"A":"abc", "B":true}
		// data will be populated as: {A: "abc", B: true}
		if err := c.Read(&data); err != nil {
			return err
		}

		profile := UserProfile {
			Id: 123213,
		}
		return c.Write(profile)
	})
	api.Get(`/user/<id:\d+>`, func(c *routing.Context) error {
		token := c.Get("JWT").(*jwt.Token)
		if token == nil {
			log.Fatal("x-auth-token must be provided")
		}

		data := &struct{
			FirstName string
			LastName string
			Email string
			IsNew bool
		}{}

		// assume the body data is: {"A":"abc", "B":true}
		// data will be populated as: {A: "abc", B: true}
		if err := c.Read(&data); err != nil {
			return err
		}

		Id64, _ := strconv.ParseUint(c.Param("id"), 10, 32)
		profile := UserProfile {
			Id: uint32(Id64),
			FirstName: data.FirstName,
			LastName: data.LastName,
			Email: data.Email,
		}
		return c.Write(profile)
	})
	api.Post("/user", func(c *routing.Context) error {
		token := c.Get("JWT").(*jwt.Token)
		if token == nil {
			log.Fatal("x-auth-token must be provided")
		}

		data := &struct{
			FirstName string
			LastName string
			Email string
			IsNew bool
		}{}

		// assume the body data is: {"A":"abc", "B":true}
		// data will be populated as: {A: "abc", B: true}
		if err := c.Read(&data); err != nil {
			return err
		}

		profile := UserProfile {
			Id: rand.Uint32(),
			FirstName: data.FirstName,
			LastName: data.LastName,
			Email: data.Email,
		}
		return c.Write(profile)
	})
	// curl -XPOST -F file=@server.go -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InRlc3QiLCJleHAiOjE0OTA3MjA1ODAsImlzcyI6ImxvY2FsaG9zdDo4MDgwIn0.lPOQZktAIDoLnHYw55jTgLEnHOGdTBqT21tpy88Zc80" localhost:8080/api/upload
	api.Post("/upload", func(c *routing.Context) error {
		c.Request.ParseMultipartForm(32 << 20)

		file, handler, err := c.Request.FormFile("file")
		if err != nil {
			fmt.Println(err)
			return nil
		}
		defer file.Close()

		f, err := os.OpenFile(handler.Filename, os.O_WRONLY|os.O_CREATE, 0664)
		if err != nil {
			fmt.Println(err)
			return nil
		}
		defer f.Close()

		io.Copy(f, file)

		return c.Write(handler.Filename)
	})

	// serve index file
	router.Get("/", file.Content("ui/index.html"))
	// serve files under the "ui" subdirectory
	router.Get("/*", file.Server(file.PathMap{
		"/": "/ui/",
	}))

	http.Handle("/", router)
	http.ListenAndServe(":" + port, nil)
}

type JwtTokenValidationError struct {
	IsValid bool
	Errors uint32
	Text string
}

func parseToken(tokenString string) (*jwt.Token, error) {
	// Parse takes the token string and a function for looking up the key. The latter is especially
	// useful if you use multiple keys for your application.  The standard is to use 'kid' in the
	// head of the token to identify which key to use, but the parsed token (head and claims) is provided
	// to the callback, providing flexibility.
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		hmacSampleSecret := []byte("asdjkh34mx0_23#@594jSrtv4")
		return hmacSampleSecret, nil
	})
	return token, err
}

func validateToken(token *jwt.Token, err error) JwtTokenValidationError {
	if token.Valid {
		fmt.Println("You look nice today")
		return JwtTokenValidationError {IsValid: true}
	} else if ve, ok := err.(*jwt.ValidationError); ok {
		if ve.Errors&jwt.ValidationErrorMalformed != 0 {
			fmt.Println("That's not even a token")

		} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
			// Token is either expired or not active yet
			fmt.Println("Timing is everything")
		} else {
			fmt.Println("Couldn't handle this token:", err)
		}
	} else {
		fmt.Println("Couldn't handle this token:", err)
	}

	tokenError := err.(*jwt.ValidationError)
	return JwtTokenValidationError {
		IsValid: false,
		Errors: tokenError.Errors,
		Text: tokenError.Inner.Error(),
	}
}

func validateTokenClaims(token *jwt.Token) {
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		fmt.Println(claims["foo"], claims["nbf"])
	} else {
		fmt.Println(token)
	}
}
