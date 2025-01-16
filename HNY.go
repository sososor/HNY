package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq" // PostgreSQLドライバ
)

var db *sql.DB

// Task構造体（habit、mainGoal、subGoalの表現）
type Task struct {
	ID   int    `json:"id"`
	Text string `json:"text"`
	Type string `json:"type"`
}

// データベース接続の初期化
func initDB() {
	var err error
	// Railwayから提供されるDATABASE_PUBLIC_URLを使う
	databaseURL := os.Getenv("DATABASE_PUBLIC_URL")
	if databaseURL == "" {
		log.Fatal("DATABASE_PUBLIC_URL is not set")
	}

	// PostgreSQLへの接続
	db, err = sql.Open("postgres", databaseURL)
	if err != nil {
		log.Fatal("Failed to connect to the database:", err)
	}

	// データベース接続の確認
	err = db.Ping()
	if err != nil {
		log.Fatal("Failed to ping the database:", err)
	}

	// テーブルが存在しない場合に作成
	createTableQuery := `
	CREATE TABLE IF NOT EXISTS tasks (
		id SERIAL PRIMARY KEY,
		text TEXT NOT NULL,
		type TEXT NOT NULL
	);`
	_, err = db.Exec(createTableQuery)
	if err != nil {
		log.Fatal("Failed to create table:", err)
	}
}

// メイン関数（APIサーバーの起動）
func main() {
	// データベース初期化
	initDB()
	defer db.Close()

	// Ginのデフォルトルーターを初期化
	r := gin.Default()

	// HTMLファイルを読み込む（テンプレートを使用）
	r.LoadHTMLFiles("templates/index.html")

	// ルート（"/"）でHTMLを表示
	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", nil)
	})

	// 静的ファイルを"/assets"で提供
	r.Static("/assets", "./assets")

	// タスク一覧を取得
	r.GET("/tasks", func(c *gin.Context) {
		var tasks []Task
		rows, err := db.Query("SELECT id, text, type FROM tasks")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to fetch tasks"})
			return
		}
		defer rows.Close()

		// データベースの行をtasksに追加
		for rows.Next() {
			var task Task
			if err := rows.Scan(&task.ID, &task.Text, &task.Type); err != nil {
				log.Println("Error scanning task:", err)
				continue
			}
			tasks = append(tasks, task)
		}

		// タスク一覧をJSONで返す
		c.JSON(http.StatusOK, tasks)
	})

	// 新しいタスクを作成
	r.POST("/tasks", func(c *gin.Context) {
		var task Task
		// リクエストボディからタスク情報をバインド
		if err := c.ShouldBindJSON(&task); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid data"})
			return
		}

		// データベースにタスクを保存
		_, err := db.Exec("INSERT INTO tasks (text, type) VALUES ($1, $2)", task.Text, task.Type)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to save task"})
			return
		}

		// 成功メッセージを返す
		c.JSON(http.StatusCreated, gin.H{"message": "Task saved successfully"})
	})

	// タスクを削除
	r.DELETE("/tasks/:id", func(c *gin.Context) {
		id := c.Param("id")
		_, err := db.Exec("DELETE FROM tasks WHERE id = $1", id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to delete task"})
			return
		}

		// 削除成功メッセージ
		c.JSON(http.StatusOK, gin.H{"message": "Task deleted successfully"})
	})

	// サーバーをポート8080で起動
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // デフォルトポート
	}
	r.Run(":" + port)
}
