package main

import (
	"log"
	"net/http"
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

var db *gorm.DB

// User モデル（ユーザー登録・認証用）
type User struct {
	ID        uint   `gorm:"primaryKey"`
	Username  string `gorm:"uniqueIndex;not null"`
	Password  string `gorm:"not null"`
	Tasks     []Task
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Task モデル（タスク情報：習慣・抱負等）
type Task struct {
	ID        uint   `gorm:"primaryKey"`
	Content   string `gorm:"not null"`
	Type      string `gorm:"not null"`       // "habit", "main", "sub"
	UserID    uint   `gorm:"index;not null"` // 所有ユーザーID
	CreatedAt time.Time
	UpdatedAt time.Time
}

// --------------------------
// JWT と認証関連
// --------------------------

var jwtKey = []byte("secret_key") // ※ 本番では環境変数などで管理

// generateJWT は指定したユーザー名で JWT を生成します。
func generateJWT(username string) (string, error) {
	claims := &jwt.StandardClaims{
		Subject:   username,
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(), // 有効期限24時間
		IssuedAt:  time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

// authRequired ミドルウェア：JWT の検証
func authRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Authorization header is missing"})
			c.Abort()
			return
		}
		// "Bearer " のプレフィックスを除去
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
			// claims["sub"] をユーザー名としてコンテキストにセット
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
// ユーザー関連エンドポイント
// --------------------------

// LoginRequest と RegisterRequest は、リクエストボディの構造体です。
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// findUserByUsername は DB からユーザーを検索します。
func findUserByUsername(username string) (*User, error) {
	var user User
	result := db.Where("username = ?", username).First(&user)
	if result.Error != nil {
		return nil, result.Error
	}
	return &user, nil
}

// checkPasswordHash は bcrypt を使用してパスワードが一致するかをチェックします。
func checkPasswordHash(inputPassword, storedPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(inputPassword))
	return err == nil
}

// createUser は新規ユーザーを DB に作成します。
func createUser(username, password string) (*User, error) {
	// パスワードをハッシュ化
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Println("Error hashing password:", err)
		return nil, err
	}
	newUser := User{
		Username: username,
		Password: string(hashedPassword),
	}
	result := db.Create(&newUser)
	if result.Error != nil {
		return nil, result.Error
	}
	return &newUser, nil
}

// login エンドポイントはユーザー認証を行い、JWT を返します。
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

// register エンドポイントは新規ユーザーを登録します。
func register(c *gin.Context) {
	var registerData RegisterRequest
	if err := c.ShouldBind(&registerData); err != nil {
		log.Println("Register bind error:", err)
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request body"})
		return
	}
	// ユーザー名の重複チェック
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
// タスク関連エンドポイント
// --------------------------

// getTasks は、認証済みユーザーのタスク一覧を DB から返します。
func getTasks(c *gin.Context) {
	username := c.GetString("username")
	user, err := findUserByUsername(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "User not found"})
		return
	}
	var tasks []Task
	result := db.Where("user_id = ?", user.ID).Find(&tasks)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Error retrieving tasks"})
		return
	}
	c.JSON(http.StatusOK, tasks)
}

// addTask は、認証済みユーザーに新規タスクを追加します。
func addTask(c *gin.Context) {
	username := c.GetString("username")
	user, err := findUserByUsername(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "User not found"})
		return
	}
	var newTask Task
	if err := c.ShouldBindJSON(&newTask); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request body"})
		return
	}
	// 新規タスクに所有ユーザーIDをセット
	newTask.UserID = user.ID
	result := db.Create(&newTask)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Error adding task"})
		return
	}
	c.JSON(http.StatusOK, newTask)
}

// deleteTask は、認証済みユーザーの指定されたタスクを DB から削除します。
func deleteTask(c *gin.Context) {
	username := c.GetString("username")
	user, err := findUserByUsername(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "User not found"})
		return
	}
	idParam := c.Param("id")
	id, err := strconv.Atoi(idParam)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid task ID"})
		return
	}
	var task Task
	result := db.First(&task, id)
	if result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": "Task not found"})
		return
	}
	// タスクの所有者が異なる場合は削除不可
	if task.UserID != user.ID {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized"})
		return
	}
	result = db.Delete(&task)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Error deleting task"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Task deleted"})
}

// --------------------------
// main 関数（サーバー起動）
// --------------------------
func main() {
	// Railway の PostgreSQL 接続文字列（※実際は環境変数などから取得することが推奨されます）
	dsn := "postgresql://postgres:KQpPHPkjBTjOTiATcxcrjxCGsxeTJlUa@roundhouse.proxy.rlwy.net:14595/railway"

	// PostgreSQL に接続
	var err error
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("failed to connect database:", err)
	}

	// モデルの自動マイグレーション
	if err := db.AutoMigrate(&User{}, &Task{}); err != nil {
		log.Fatal("failed to auto-migrate:", err)
	}

	r := gin.Default()
	r.Use(cors.Default())

	// HTMLテンプレートの読み込み（templates フォルダ内）
	r.LoadHTMLGlob("templates/*")

	// ルート "/" ではログインページ (login.html) を表示
	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", gin.H{
			"title":      "ログインページ",
			"action":     "/login",
			"buttonText": "ログイン",
		})
	})

	// /register ではアカウント作成用のページ (login.html) を表示
	r.GET("/register", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", gin.H{
			"title":      "アカウント作成ページ",
			"action":     "/register",
			"buttonText": "登録",
		})
	})

	// /index は保護ページとして HTML を返す（認証チェックはクライアント側で実施）
	r.GET("/index", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", nil)
	})

	// ユーザー認証エンドポイント
	r.POST("/login", login)
	r.POST("/register", register)

	// タスク管理エンドポイント（認証ミドルウェア適用）
	taskGroup := r.Group("/tasks")
	taskGroup.Use(authRequired())
	{
		taskGroup.GET("", getTasks)
		taskGroup.POST("", addTask)
		taskGroup.DELETE("/:id", deleteTask)
	}

	// サーバー起動
	if err := r.Run(":8080"); err != nil {
		log.Fatal("Server startup failed:", err)
	}
}
