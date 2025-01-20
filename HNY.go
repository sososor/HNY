package main

import (
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

// -----------------------
// ユーザー関連の定義
// -----------------------

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

var jwtKey = []byte("secret_key")

var users = []User{
	{Username: "user1", Password: "$2a$10$TtF1tw2PiCwn6c5pk0toZuXyHZ2UMlXgNhVe94SxVdi0lLZ56a7lC"}, // password123
	{Username: "user2", Password: "$2a$10$w3FceT5FS9fMw.WsXg6z4uWogd8DPVpI6Sckpw6rK2mtmb3rOxkAu"}, // password456
}

// generateJWT は指定したユーザー名で JWT を生成します。
func generateJWT(username string) (string, error) {
	claims := &jwt.StandardClaims{
		Subject:   username,
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

// findUserByUsername はユーザー名からユーザーを検索します。
func findUserByUsername(username string) (*User, error) {
	for _, user := range users {
		if user.Username == username {
			return &user, nil
		}
	}
	return nil, errors.New("user not found")
}

// checkPasswordHash は bcrypt を使用してパスワードが一致するかをチェックします。
func checkPasswordHash(inputPassword, storedPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(inputPassword))
	return err == nil
}

// createUser は新規ユーザーを作成します。
func createUser(username, password string) (User, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Println("Error hashing password:", err)
		return User{}, err
	}
	newUser := User{Username: username, Password: string(hashedPassword)}
	users = append(users, newUser)
	return newUser, nil
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

// -----------------------
// 認証ミドルウェア
// -----------------------

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
			// claims["sub"] をユーザー名としてコンテキストにセット
			c.Set("username", claims["sub"])
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid token claims"})
			c.Abort()
			return
		}
		c.Next()
	}
}

// -----------------------
// タスク関連の定義（ユーザー毎の管理）
// -----------------------

// Task はタスクの構造体です。
type Task struct {
	ID      int    `json:"id"`
	Content string `json:"content"`
	Type    string `json:"type"` // "habit", "main", "sub"
}

// userTasks は、各ユーザーごとにタスクを保持するマップです。
var userTasks = make(map[string][]Task)
var taskIDCounter int = 1

// getTasks は、認証済みユーザーのタスク一覧を返します。
func getTasks(c *gin.Context) {
	username := c.GetString("username")
	tasksForUser, ok := userTasks[username]
	if !ok {
		tasksForUser = []Task{}
	}
	c.JSON(http.StatusOK, tasksForUser)
}

// addTask は、認証済みユーザーに新規タスクを追加します。
func addTask(c *gin.Context) {
	username := c.GetString("username")
	var newTask Task
	if err := c.ShouldBindJSON(&newTask); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request body"})
		return
	}
	newTask.ID = taskIDCounter
	taskIDCounter++
	// 各ユーザーごとのタスクスライスに追加
	userTasks[username] = append(userTasks[username], newTask)
	c.JSON(http.StatusOK, newTask)
}

// deleteTask は、認証済みユーザーの指定されたタスクを削除します。
func deleteTask(c *gin.Context) {
	username := c.GetString("username")
	idParam := c.Param("id")
	id, err := strconv.Atoi(idParam)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid task ID"})
		return
	}
	tasksForUser, ok := userTasks[username]
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"message": "Task not found"})
		return
	}
	for i, task := range tasksForUser {
		if task.ID == id {
			// スライスから削除
			userTasks[username] = append(tasksForUser[:i], tasksForUser[i+1:]...)
			c.JSON(http.StatusOK, gin.H{"message": "Task deleted"})
			return
		}
	}
	c.JSON(http.StatusNotFound, gin.H{"message": "Task not found"})
}

func main() {
	r := gin.Default()
	r.Use(cors.Default())
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

	// /index は保護ページとしてHTMLを返す（認証チェックはクライアント側で実施）
	r.GET("/index", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", nil)
	})

	r.POST("/login", login)
	r.POST("/register", register)

	// タスク管理エンドポイント（認証ミドルウェアを適用）
	taskGroup := r.Group("/tasks")
	taskGroup.Use(authRequired())
	{
		taskGroup.GET("", getTasks)
		taskGroup.POST("", addTask)
		taskGroup.DELETE("/:id", deleteTask)
	}

	if err := r.Run(":8080"); err != nil {
		log.Fatal("Server startup failed:", err)
	}
}
