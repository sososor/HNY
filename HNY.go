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

// User はユーザー情報
type User struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	Username   string    `gorm:"uniqueIndex:idx_users_username;not null" json:"username"`
	Password   string    `gorm:"not null" json:"-"`          // パスワードは返さない
	SchemaName string    `gorm:"not null" json:"schemaName"` // tenant_ユーザー名
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

// Task はタスク情報
type Task struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Content   string    `gorm:"not null"  json:"content"`
	Type      string    `gorm:"not null"  json:"type"`   // "habit", "main", "sub"
	UserID    uint      `gorm:"not null"  json:"userId"` // 中央DBのUser.ID
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// --------------------------
// JWT と認証関連
// --------------------------
var jwtKey = []byte("secret_key") // 本番運用では環境変数などで管理してください

// generateJWT はユーザー名を含むJWTを生成
func generateJWT(username string) (string, error) {
	claims := &jwt.StandardClaims{
		Subject:   username,
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		IssuedAt:  time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

// authRequired は認証ミドルウェア
func authRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Authorization header is missing"})
			c.Abort()
			return
		}
		// "Bearer "の除去
		tokenString = strings.TrimPrefix(tokenString, "Bearer ")
		tokenString = strings.TrimSpace(tokenString)

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
// ユーザー認証関連
// --------------------------
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// findUserByUsername は中央DBからユーザーを検索
func findUserByUsername(username string) (*User, error) {
	var user User
	result := centralDB.Where("username = ?", username).First(&user)
	if result.Error != nil {
		return nil, result.Error
	}
	return &user, nil
}

// checkPasswordHash はパスワードが一致するか確認
func checkPasswordHash(inputPassword, storedPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(inputPassword))
	return err == nil
}

// createUser は新規ユーザーを作成し、専用スキーマを用意
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
	// 中央DBにユーザーを追加
	if err := centralDB.Create(&newUser).Error; err != nil {
		return nil, err
	}
	// スキーマ作成
	if err := centralDB.Exec(fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", schema)).Error; err != nil {
		log.Printf("Failed to create schema %s: %v", schema, err)
		return nil, err
	}
	// テナント用DBへ接続 (search_path切替)
	tenantDB, err := newTenantDB(schema)
	if err != nil {
		log.Printf("Failed to get tenant DB for schema %s: %v", schema, err)
		return nil, err
	}
	// tenant用 Task テーブルのAutoMigrate
	if err := tenantDB.AutoMigrate(&Task{}); err != nil {
		log.Printf("Failed to auto-migrate tenant schema %s: %v", schema, err)
		return nil, err
	}
	return &newUser, nil
}

// login エンドポイント (POST /login)
func login(c *gin.Context) {
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

// register エンドポイント (POST /register)
func register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request body"})
		return
	}
	_, err := findUserByUsername(req.Username)
	// 既にユーザーが存在する
	if err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Username already taken"})
		return
	}
	user, err := createUser(req.Username, req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Error creating user"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message":     "User registered successfully",
		"user":        user,
		"redirectUrl": "/",
	})
}

// --------------------------
// タスク関連
// --------------------------

// newTenantDB は DSN に search_path=schema を追加して開く
func newTenantDB(schema string) (*gorm.DB, error) {
	dsn := strings.TrimSpace(os.Getenv("DATABASE_PUBLIC_URL"))
	if dsn == "" {
		return nil, fmt.Errorf("DATABASE_PUBLIC_URL not set")
	}
	var dsnWithSchema string
	if strings.Contains(dsn, "?") {
		// DSNに既にクエリパラメータがある場合
		dsnWithSchema = fmt.Sprintf("%s&search_path=%s", dsn, schema)
	} else {
		dsnWithSchema = fmt.Sprintf("%s?search_path=%s", dsn, schema)
	}
	return gorm.Open(postgres.Open(dsnWithSchema), &gorm.Config{})
}

// getTasks エンドポイント (GET /tasks)
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
	// タスクを種類別に分割して返す
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

// addTask エンドポイント (POST /tasks)
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
	// 新しいタスクにUserIDをセット
	req.UserID = user.ID
	if err := tenantDB.Create(&req).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Error adding task"})
		return
	}
	c.JSON(http.StatusOK, req)
}

// deleteTask エンドポイント (DELETE /tasks/:id)
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
		log.Fatal("DATABASE_PUBLIC_URL is not set")
	}
	// 中央DB接続
	var err error
	centralDB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("failed to connect to central database: %v", err)
	}
	if err := centralDB.AutoMigrate(&User{}); err != nil {
		log.Fatalf("failed to auto-migrate centralDB: %v", err)
	}
	// 古い unique constraint があれば削除 (uni_users_username)
	if centralDB.Migrator().HasConstraint(&User{}, "uni_users_username") {
		if err := centralDB.Migrator().DropConstraint(&User{}, "uni_users_username"); err != nil {
			log.Printf("Warning: failed to drop old constraint 'uni_users_username': %v", err)
		}
	}

	// Gin
	r := gin.Default()
	r.Use(cors.Default())

	// テンプレート読み込み
	r.LoadHTMLGlob("templates/*")

	// ルート
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
	// 認証エンドポイント
	r.POST("/login", login)
	r.POST("/register", register)
	// タスク管理 (認証要)
	taskGroup := r.Group("/tasks")
	taskGroup.Use(authRequired())
	{
		taskGroup.GET("", getTasks)          // GET /tasks
		taskGroup.POST("", addTask)          // POST /tasks
		taskGroup.DELETE("/:id", deleteTask) // DELETE /tasks/:id
	}

	// 起動
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
