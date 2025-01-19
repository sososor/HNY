package main

import (
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

// ユーザー情報を保持する構造体
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// リクエストデータの構造体
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// JWTの秘密鍵
var jwtKey = []byte("secret_key") // 本番環境では秘密鍵を安全に管理してください

// 仮のユーザー情報（データベースから取得する部分を実装する場合）
var users = []User{
	{Username: "user1", Password: "password123"},
	{Username: "user2", Password: "password456"},
}

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
	// 本番環境ではパスワードをハッシュ化して検証するべきです
	return inputPassword == storedPassword
}

// ログインエンドポイント
func login(c *gin.Context) {
	var loginData LoginRequest

	// リクエストボディをJSONとしてバインド
	if err := c.ShouldBindJSON(&loginData); err != nil {
		log.Println("Login bind error:", err) // エラーログを追加
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request body"})
		return
	}

	log.Println("Login request received:", loginData) // リクエストの内容をログに出力

	// ユーザー情報の取得
	user, err := findUserByUsername(loginData.Username)
	if err != nil {
		log.Println("User not found:", err)
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid username or password"})
		return
	}

	// パスワードの確認
	if !checkPasswordHash(loginData.Password, user.Password) {
		log.Println("Password mismatch")
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid username or password"})
		return
	}

	// JWTトークンの生成
	token, err := generateJWT(user.Username)
	if err != nil {
		log.Println("Error generating JWT:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Internal server error"})
		return
	}

	// 成功レスポンス
	c.JSON(http.StatusOK, gin.H{
		"message": "Login successful",
		"token":   token,
	})
}

func main() {
	r := gin.Default()

	// ログインエンドポイントを設定
	r.POST("/login", login)

	// サーバー起動
	if err := r.Run(":8080"); err != nil {
		log.Fatal("Server startup failed:", err)
	}
}
