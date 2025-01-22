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

var centralDB *gorm.DB

type User struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	Username   string    `gorm:"uniqueIndex:idx_users_username;not null" json:"username"`
	Password   string    `gorm:"not null" json:"-"` // パスワードは返さない
	SchemaName string    `gorm:"not null" json:"schemaName"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

type Task struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Content   string    `gorm:"not null" json:"content"`
	Type      string    `gorm:"not null" json:"type"` // "habit", "main", "sub"
	UserID    uint      `gorm:"not null" json:"userId"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// --------------------------
// JWT と認証関連
// --------------------------

var jwtKey = []byte("secret_key") // 本番では環境変数等で管理してください

func generateJWT(username string) (string, error) {
	claims := &jwt.StandardClaims{
		Subject:   username,
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		IssuedAt:  time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

func authRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Authorization header is missing"})
			c.Abort()
			return
		}
		// "Bearer " の除去と前後の空白を削除
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
			username, _ := claims["sub"].(string)
			c.Set("username", username)
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid token claims"})
			c.Abort()
			return
		}
		c.Next()
	}
}

// --------------------------
// ユーザー認証関連エンドポイント
// --------------------------

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func findUserByUsername(username string) (*User, error) {
	var user User
	result := centralDB.Where("username = ?", username).First(&user)
	if result.Error != nil {
		return nil, result.Error
	}
	return &user, nil
}

func checkPasswordHash(inputPassword, storedPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(inputPassword))
	return err == nil
}

func createUser(username, password string) (*User, error) {
	// ハッシュ化
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Println("Error hashing password:", err)
		return nil, err
	}
	// スキーマ名は "tenant_<username>" とする
	schema := fmt.Sprintf("tenant_%s", username)
	newUser := User{
		Username:   username,
		Password:   string(hashedPassword),
		SchemaName: schema,
	}
	// 中央DBにユーザーを作成
	if err := centralDB.Create(&newUser).Error; err != nil {
		return nil, err
	}
	// スキーマ作成
	if err := centralDB.Exec(fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", schema)).Error; err != nil {
		log.Printf("Failed to create schema %s: %v", schema, err)
		return nil, err
	}
	// テナント用DBを生成（DSN に search_path を追加）
	tenantDB, err := newTenantDB(schema)
	if err != nil {
		log.Printf("Failed to get tenant DB for schema %s: %v", schema, err)
		return nil, err
	}
	// Taskテーブル作成
	if err := tenantDB.AutoMigrate(&Task{}); err != nil {
		log.Printf("Failed to auto-migrate tenant schema %s: %v", schema, err)
		return nil, err
	}
	return &newUser, nil
}

func loginHandler(c *gin.Context) {
	var loginData LoginRequest
	if err := c.ShouldBindJSON(&loginData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request body"})
		return
	}
	user, err := findUserByUsername(loginData.Username)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid username or password"})
		return
	}
	if !checkPasswordHash(loginData.Password, user.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid username or password"})
		return
	}
	token, err := generateJWT(user.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Error generating token"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message":     "Login successful",
		"token":       token,
		"redirectUrl": "/index",
	})
}

func registerHandler(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request body"})
		return
	}
	// ユーザーの存在確認
	_, err := findUserByUsername(req.Username)
	if err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Username already taken"})
		return
	}
	user, err := createUser(req.Username, req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Error creating user"})
		return
	}
	// 登録完了後、ログインページへリダイレクト（クライアント側のJSで処理）
	c.JSON(http.StatusOK, gin.H{
		"message":     "User registered successfully",
		"user":        user,
		"redirectUrl": "/",
	})
}

// --------------------------
// タスク関連エンドポイント
// --------------------------

// newTenantDB は DSN に search_path を追加してテナント用DBへ接続する
func newTenantDB(schema string) (*gorm.DB, error) {
	dsn := strings.TrimSpace(os.Getenv("DATABASE_PUBLIC_URL"))
	if dsn == "" {
		log.Fatal("DATABASE_PUBLIC_URL is not set")
	}
	// 既にクエリパラメータがある場合は "&" を、それ以外は "?" を使用する
	var dsnWithSchema string
	if strings.Contains(dsn, "?") {
		dsnWithSchema = fmt.Sprintf("%s&search_path=%s", dsn, schema)
	} else {
		dsnWithSchema = fmt.Sprintf("%s?search_path=%s", dsn, schema)
	}
	return gorm.Open(postgres.Open(dsnWithSchema), &gorm.Config{})
}

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
	// タスクを種類別に振り分ける
	habitTasks := []Task{}
	mainTasks := []Task{}
	subTasks := []Task{}
	for _, t := range tasks {
		switch t.Type {
		case "habit":
			habitTasks = append(habitTasks, t)
		case "main":
			mainTasks = append(mainTasks, t)
		case "sub":
			subTasks = append(subTasks, t)
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"habits": habitTasks,
		"main":   mainTasks,
		"sub":    subTasks,
	})
}

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
	var req Task
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request body"})
		return
	}
	req.UserID = user.ID
	if err := tenantDB.Create(&req).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Error adding task"})
		return
	}
	c.JSON(http.StatusOK, req)
}

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
	dsn := strings.TrimSpace(os.Getenv("DATABASE_PUBLIC_URL"))
	if dsn == "" {
		log.Fatal("DATABASE_PUBLIC_URL が設定されていません。正しい DSN を環境変数に設定してください。")
	}
	// 例: postgresql://postgres:WzOmuEUbEDlIGBJgCvoXbowDBEkulsGO@junction.proxy.rlwy.net:44586/railway?sslmode=require
	var err error
	centralDB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("failed to connect to central database: %v", err)
	}
	if err := centralDB.AutoMigrate(&User{}); err != nil {
		log.Fatalf("failed to auto-migrate centralDB: %v", err)
	}
	// 古いユニーク制約があれば削除（必要に応じて）
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

	// ログイン & アカウント作成ページ
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

	r.POST("/login", loginHandler)
	r.POST("/register", registerHandler)

	// タスク管理エンドポイント（認証必須）
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
