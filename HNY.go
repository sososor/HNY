package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var jwtKey = []byte("your_secret_key")
var db *sql.DB

// User構造体
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

// Credentials構造体
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Claims構造体
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

// Task構造体
type Task struct {
	ID   int    `json:"id"`
	Text string `json:"text"`
	Type string `json:"type"`
}

// LoginRequest構造体（ログインリクエスト）
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// データベース接続の初期化
func initDB() {
	var err error
	databaseURL := os.Getenv("DATABASE_PUBLIC_URL")
	if databaseURL == "" {
		log.Fatal("DATABASE_PUBLIC_URL is not set")
	}

	db, err = sql.Open("postgres", databaseURL)
	if err != nil {
		log.Fatal("Failed to connect to the database:", err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatal("Failed to ping the database:", err)
	}

	createTableQuery := `
	CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		email TEXT UNIQUE NOT NULL
	);
	CREATE TABLE IF NOT EXISTS tasks (
		id SERIAL PRIMARY KEY,
		text TEXT NOT NULL,
		type TEXT NOT NULL,
		username TEXT REFERENCES users(username)
	);`
	_, err = db.Exec(createTableQuery)
	if err != nil {
		log.Fatal("Failed to create tables:", err)
	}
}

func main() {
	initDB()
	defer db.Close()

	r := gin.Default()

	// テンプレートのパスを設定
	r.LoadHTMLGlob("templates/*")

	// ルートパスでログインページを表示
	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "Log.html", gin.H{
			"title":      "ログインページ",
			"action":     "/login",
			"buttonText": "ログイン",
		})
	})

	// 新規登録ページ
	r.GET("/register", func(c *gin.Context) {
		c.HTML(http.StatusOK, "Log.html", gin.H{
			"title":      "アカウント作成",
			"action":     "/register",
			"buttonText": "アカウント作成",
		})
	})

	// 登録処理
	r.POST("/register", register)

	// ログイン処理
	r.POST("/login", login)

	// 認証が必要なエンドポイント
	auth := r.Group("/")
	auth.Use(authMiddleware())
	auth.GET("/tasks", getTasks)
	auth.POST("/tasks", createTask)
	auth.DELETE("/tasks/:id", deleteTask)

	// ポート設定
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	r.Run(":" + port)
}

// パスワードのハッシュ化
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// パスワードの検証
func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// アカウント登録
func register(c *gin.Context) {
	var user User
	// フォームデータをパース
	username := c.DefaultPostForm("username", "")
	password := c.DefaultPostForm("password", "")

	if username == "" || password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "ユーザー名またはパスワードが空です"})
		return
	}

	// ユーザー情報を構造体にセット
	user.Username = username
	user.Password = password

	// パスワードのハッシュ化
	hashedPassword, err := hashPassword(user.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "パスワードのハッシュ化に失敗しました"})
		return
	}

	// データベースにユーザー情報を挿入
	query := `INSERT INTO users (username, password) VALUES ($1, $2)`
	_, err = db.Exec(query, user.Username, hashedPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "ユーザーの作成に失敗しました"})
		return
	}

	// 登録成功
	c.JSON(http.StatusOK, gin.H{
		"message":     "User registered successfully",
		"redirectUrl": "/login", // ログインページにリダイレクト
	})
}

// ログイン
func login(c *gin.Context) {
	var loginData LoginRequest
	if err := c.ShouldBindJSON(&loginData); err != nil {
		log.Println("Login bind error:", err)
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request body"})
		return
	}

	// ユーザー情報をデータベースで照会する処理
	user, err := findUserByUsername(loginData.Username)
	if err != nil {
		log.Println("User not found:", err)
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid username or password"})
		return
	}

	// パスワードチェック
	if !checkPasswordHash(loginData.Password, user.Password) {
		log.Println("Password mismatch")
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid username or password"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":     "Login successful",
		"redirectUrl": "/dashboard", // リダイレクト先
	})
}

// JWT 認証ミドルウェア
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr := c.GetHeader("Authorization")
		if tokenStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Missing token"})
			c.Abort()
			return
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid token"})
			c.Abort()
			return
		}

		c.Set("username", claims.Username)
		c.Next()
	}
}

// ユーザー名でユーザーを検索
func findUserByUsername(username string) (User, error) {
	var user User
	query := `SELECT username, password, email FROM users WHERE username = $1`
	err := db.QueryRow(query, username).Scan(&user.Username, &user.Password, &user.Email)
	if err != nil {
		if err == sql.ErrNoRows {
			return User{}, nil // ユーザーが存在しない場合
		}
		return User{}, err
	}
	return user, nil
}

// タスク一覧取得
func getTasks(c *gin.Context) {
	username := c.GetString("username")

	var tasks []Task
	rows, err := db.Query("SELECT id, text, type FROM tasks WHERE username = $1", username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to fetch tasks"})
		return
	}
	defer rows.Close()

	for rows.Next() {
		var task Task
		if err := rows.Scan(&task.ID, &task.Text, &task.Type); err != nil {
			log.Println("Error scanning task:", err)
			continue
		}
		tasks = append(tasks, task)
	}

	c.JSON(http.StatusOK, tasks)
}

// 新しいタスク作成
func createTask(c *gin.Context) {
	username := c.GetString("username")

	var task Task
	if err := c.BindJSON(&task); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid data"})
		return
	}

	_, err := db.Exec("INSERT INTO tasks (text, type, username) VALUES ($1, $2, $3)", task.Text, task.Type, username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to save task"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "Task saved successfully"})
}

// タスク削除
func deleteTask(c *gin.Context) {
	id := c.Param("id")
	username := c.GetString("username")

	_, err := db.Exec("DELETE FROM tasks WHERE id = $1 AND username = $2", id, username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to delete task"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Task deleted successfully"})
}
