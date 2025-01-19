package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

// JWTのトークンを検証するミドルウェア
func authRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Authorization header is missing"})
			c.Abort()
			return
		}

		// "Bearer <token>" 形式のトークンを処理
		tokenString = tokenString[len("Bearer "):]

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// JWTの署名方法がHS256かを確認
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return jwtKey, nil // jwtSecret を jwtKey に変更
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid token"})
			c.Abort()
			return
		}

		// トークンが有効であれば、次のハンドラーを呼び出す
		c.Next()
	}
}

// ユーザー情報を保持する構造体（emailフィールドは削除）
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// リクエストデータの構造体（emailフィールドは削除）
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// アカウント作成リクエストデータの構造体（emailフィールドは削除）
type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// JWTの秘密鍵
var jwtKey = []byte("secret_key") // 本番環境では秘密鍵を安全に管理してください

// 仮のユーザー情報（データベースから取得する部分を実装する場合）
var users = []User{
	{Username: "user1", Password: "$2a$10$TtF1tw2PiCwn6c5pk0toZuXyHZ2UMlXgNhVe94SxVdi0lLZ56a7lC"}, // password123
	{Username: "user2", Password: "$2a$10$w3FceT5FS9fMw.WsXg6z4uWogd8DPVpI6Sckpw6rK2mtmb3rOxkAu"}, // password456
}

// 仮のブラックリストでJWTトークンを無効化
var tokenBlacklist = make(map[string]bool)

// JWTを生成する関数
func generateJWT(username string) (string, error) {
	// JWTトークンのペイロード
	claims := &jwt.StandardClaims{
		Subject:   username,
		ExpiresAt: time.Now().Add(time.Hour * 24).Unix(), // 24時間後にトークンが期限切れ
	}

	// トークンを生成
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

// JWTトークンを無効化する関数
func invalidateJWT(token string) {
	tokenBlacklist[token] = true
}

// JWTトークンが無効化されているか確認する関数
func isTokenBlacklisted(token string) bool {
	return tokenBlacklist[token]
}

// JWTトークンの検証
func validateJWT(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Authorization header missing"})
		c.Abort()
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	log.Println("Token string:", tokenString) // トークン文字列をログに出力

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		log.Println("Error parsing token:", err)
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid or expired token"})
		c.Abort()
		return
	}

	if !token.Valid || isTokenBlacklisted(tokenString) {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid or expired token"})
		c.Abort()
		return
	}

	c.Set("username", token.Claims.(jwt.MapClaims)["sub"])
	c.Next()
}

// ユーザーをデータベース（仮の配列）で検索する関数
func findUserByUsername(username string) (*User, error) {
	for _, user := range users {
		if user.Username == username {
			return &user, nil
		}
	}
	return nil, errors.New("user not found")
}

// パスワードが一致するかを確認する関数
func checkPasswordHash(inputPassword, storedPassword string) bool {
	// bcryptでパスワードをハッシュ化して比較
	err := bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(inputPassword))
	return err == nil
}

// 新規ユーザーを追加する関数
func createUser(username, password string) (User, error) {
	// パスワードのハッシュ化
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Println("Error hashing password:", err) // エラーログを追加
		return User{}, err
	}

	// 新しいユーザーを作成
	newUser := User{Username: username, Password: string(hashedPassword)}
	users = append(users, newUser)
	return newUser, nil
}

// ログインエンドポイント
func login(c *gin.Context) {
	var loginData LoginRequest

	if err := c.ShouldBindJSON(&loginData); err != nil {
		log.Println("Login bind error:", err)
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request body"})
		return
	}

	user, err := findUserByUsername(loginData.Username)
	if err != nil {
		log.Println("User not found:", err)
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid username or password"})
		return
	}

	if !checkPasswordHash(loginData.Password, user.Password) {
		log.Println("Password mismatch")
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid username or password"})
		return
	}

	token, err := generateJWT(user.Username)
	if err != nil {
		log.Println("Error generating JWT:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":     "Login successful",
		"token":       token,
		"redirectUrl": "/index", // リダイレクト先のURLを指定
	})
}

// アカウント作成エンドポイント
func register(c *gin.Context) {
	var registerData RegisterRequest

	if err := c.ShouldBind(&registerData); err != nil {
		log.Println("Register bind error:", err)
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request body"})
		return
	}

	_, err := findUserByUsername(registerData.Username)
	if err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Username already taken"})
		return
	}

	newUser, err := createUser(registerData.Username, registerData.Password)
	if err != nil {
		log.Println("Error creating user:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Error creating user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":     "User registered successfully",
		"user":        newUser,
		"redirectUrl": "/", // 登録後にログインページにリダイレクト
	})
}

// ログアウトエンドポイント
func logout(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Authorization header missing"})
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	invalidateJWT(tokenString) // トークンを無効化
	c.JSON(http.StatusOK, gin.H{"message": "Logout successful"})
}

func main() {
	r := gin.Default()
	r.Use(cors.Default())
	// HTMLテンプレートを読み込む
	r.LoadHTMLGlob("templates/*")

	// GET / ルートを設定
	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", gin.H{
			"title":      "ログインページ",
			"action":     "/login",
			"buttonText": "ログイン",
		})
	})

	// /register へのアクセスを処理
	r.GET("/register", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", gin.H{
			"title":      "アカウント作成ページ",
			"action":     "/register",
			"buttonText": "登録",
		})
	})

	// 認証を要求するルートにミドルウェアを適用
	r.GET("/index", authRequired(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "Welcome to the protected /index route"})
	})

	// ログアウトエンドポイントを設定
	r.POST("/logout", logout)

	// /login への POST リクエストを処理
	r.POST("/login", login)

	// /register への POST リクエストを処理
	r.POST("/register", register)

	// サーバー起動
	if err := r.Run(":8080"); err != nil {
		log.Fatal("Server startup failed:", err)
	}
}
