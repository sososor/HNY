package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// --------------------------
// DB接続とモデル定義
// --------------------------

// centralDB でユーザー情報を管理（中央DB）
var centralDB *gorm.DB

// User は認証用のユーザー情報（中央DBに保存）
type User struct {
	ID         uint   `gorm:"primaryKey"`
	Username   string `gorm:"uniqueIndex:idx_users_username;not null"`
	Password   string `gorm:"not null"`
	SchemaName string `gorm:"not null"` // tenant_<username> のようなスキーマ名
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// Task はタスク情報（各ユーザー専用のスキーマ内にテーブルを作成）
type Task struct {
	ID        uint   `gorm:"primaryKey"`
	Content   string `gorm:"not null"`
	Type      string `gorm:"not null"` // "habit", "main", "sub"
	UserID    uint   `gorm:"not null"` // 中央DBの User.ID （参考）
	CreatedAt time.Time
	UpdatedAt time.Time
}

// --------------------------
// JWT と認証関連
// --------------------------

var jwtKey = []byte("secret_key") // 本番では環境変数で管理する

// generateJWT は指定したユーザー名で JWT を生成します
func generateJWT(username string) (string, error) {
	claims := &jwt.StandardClaims{
		Subject:   username,
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		IssuedAt:  time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

// authRequired は JWT を検証するミドルウェアです
func authRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Authorization header is missing"})
			c.Abort()
			return
		}
		tokenString = strings.TrimSpace(strings.TrimPrefix(tokenString, "Bearer "))
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid token"})
			c.Abort()
			return
		}
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			c.Set("username", claims["sub"].(string))
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid token claims"})
			c.Abort()
			return
		}
		c.Next()
	}
}

// --------------------------
// ユーザー関連エンドポイント（中央DBを操作）
// --------------------------

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// findUserByUsername は中央DBからユーザーを検索します
func findUserByUsername(username string) (*User, error) {
	var user User
	result := centralDB.Where("username = ?", username).First(&user)
	if result.Error != nil {
		return nil, result.Error
	}
	return &user, nil
}

// checkPasswordHash はパスワードが一致するか検証します
func checkPasswordHash(inputPassword, storedPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(inputPassword))
	return err == nil
}

// createUser は中央DBに新規ユーザーを作成し、専用スキーマも作成します
func createUser(username, password string) (*User, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Println("Error hashing password:", err)
		return nil, err
	}
	schema := fmt.Sprintf("tenant_%s", username)
	newUser := User{
		Username:   username,
		Password:   string(hashedPassword),
		SchemaName: schema,
	}
	result := centralDB.Create(&newUser)
	if result.Error != nil {
		return nil, result.Error
	}

	// 専用スキーマの作成
	if err := centralDB.Exec(fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", schema)).Error; err != nil {
		log.Printf("Failed to create schema %s: %v", schema, err)
		return nil, err
	}

	// tenant 用の DB 接続を作成（search_path を専用スキーマに切り替え）
	tenantDB, err := newTenantDB(schema)
	if err != nil {
		log.Printf("Failed to get tenant DB for schema %s: %v", schema, err)
		return nil, err
	}
	// tenant 用に Task テーブルを自動マイグレーション
	if err := tenantDB.AutoMigrate(&Task{}); err != nil {
		log.Printf("Failed to auto-migrate tenant schema %s: %v", schema, err)
		return nil, err
	}
	return &newUser, nil
}

// login エンドポイント
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
		"redirectUrl": "/index",
	})
}

// register エンドポイント
func register(c *gin.Context) {
	var registerData RegisterRequest
	if err := c.ShouldBind(&registerData); err != nil {
		log.Println("Register bind error:", err)
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request body"})
		return
	}
	// 重複チェック
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
		"redirectUrl": "/",
	})
}

// --------------------------
// タスク関連エンドポイント（各ユーザーの専用スキーマを利用）
// --------------------------

// newTenantDB は同じ DSN で tenant 用に search_path を設定した接続を返します
func newTenantDB(schema string) (*gorm.DB, error) {
	dsn := os.Getenv("DATABASE_PUBLIC_URL")
	if dsn == "" {
		log.Fatal("DATABASE_PUBLIC_URL が設定されていません。")
	}
	// 例：sslmode が必要ならクエリパラメータとして追加する
	dsnWithSchema := fmt.Sprintf("%s?search_path=%s", dsn, schema)
	tenantDB, err := gorm.Open(postgres.Open(dsnWithSchema), &gorm.Config{})
	if err != nil {
		return nil, err
	}
	return tenantDB, nil
}

// getTasks は、ログイン中のユーザーのタスク一覧を専用スキーマから返す
func getTasks(c *gin.Context) {
	username := c.GetString("username")
	user, err := findUserByUsername(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "User not found"})
		return
	}
	tenantDB, err := newTenantDB(user.SchemaName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Error connecting to tenant DB"})
		return
	}
	var tasks []Task
	if err := tenantDB.Find(&tasks).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Error retrieving tasks"})
		return
	}
	c.JSON(http.StatusOK, tasks)
}

// addTask は、ログイン中のユーザーの専用スキーマにタスクを追加する
func addTask(c *gin.Context) {
	username := c.GetString("username")
	user, err := findUserByUsername(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "User not found"})
		return
	}
	tenantDB, err := newTenantDB(user.SchemaName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Error connecting to tenant DB"})
		return
	}
	var newTask Task
	if err := c.ShouldBindJSON(&newTask); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request body"})
		return
	}
	newTask.UserID = user.ID
	if err := tenantDB.Create(&newTask).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Error adding task"})
		return
	}
	c.JSON(http.StatusOK, newTask)
}

// deleteTask は、ログイン中のユーザーの専用スキーマからタスクを削除する
func deleteTask(c *gin.Context) {
	username := c.GetString("username")
	user, err := findUserByUsername(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "User not found"})
		return
	}
	tenantDB, err := newTenantDB(user.SchemaName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Error connecting to tenant DB"})
		return
	}
	idParam := c.Param("id")
	id, err := strconv.Atoi(idParam)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid task ID"})
		return
	}
	var task Task
	if err := tenantDB.First(&task, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": "Task not found"})
		return
	}
	if err := tenantDB.Delete(&task).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Error deleting task"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Task deleted"})
}

func main() {
	// DATABASE_PUBLIC_URL 環境変数に正しいDSNが設定されているか確認（例：
	// "postgresql://postgres:password@roundhouse.proxy.rlwy.net:14595/railway?sslmode=require"）
	dsn := os.Getenv("DATABASE_PUBLIC_URL")
	if dsn == "" {
		log.Fatal("DATABASE_PUBLIC_URL が設定されていません。正しい DSN を環境変数に設定してください。")
	}

	var err error
	centralDB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("failed to connect to central database: %v", err)
	}

	if err := centralDB.AutoMigrate(&User{}); err != nil {
		log.Fatalf("failed to auto-migrate centralDB: %v", err)
	}

	if centralDB.Migrator().HasConstraint(&User{}, "uni_users_username") {
		if err := centralDB.Migrator().DropConstraint(&User{}, "uni_users_username"); err != nil {
			log.Printf("Warning: failed to drop old constraint 'uni_users_username': %v", err)
		} else {
			log.Println("Dropped old constraint 'uni_users_username'")
		}
	}

	r := gin.Default()
	r.Use(cors.Default())
	r.LoadHTMLGlob("templates/*")

	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", gin.H{
			"title":      "ログインページ",
			"action":     "/login",
			"buttonText": "ログイン",
		})
	})
	r.GET("/register", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", gin.H{
			"title":      "アカウント作成ページ",
			"action":     "/register",
			"buttonText": "登録",
		})
	})
	r.GET("/index", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", nil)
	})

	r.POST("/login", login)
	r.POST("/register", register)

	taskGroup := r.Group("/tasks")
	taskGroup.Use(authRequired())
	{
		taskGroup.GET("", getTasks)
		taskGroup.POST("", addTask)
		taskGroup.DELETE("/:id", deleteTask)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	addr := "0.0.0.0:" + port
	log.Printf("Server is running on %s", addr)
	if err := r.Run(addr); err != nil {
		log.Fatalf("Server startup failed: %v", err)
	}
}
