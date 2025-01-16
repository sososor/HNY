package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq" // PostgreSQL driver
)

var db *sql.DB

// Task structure to represent habit, mainGoal, and subGoal
type Task struct {
	ID   int    `json:"id"`
	Text string `json:"text"`
	Type string `json:"type"`
}

func initDB() {
	var err error
	// Railwayから提供されるDATABASE_URLを使う
	databaseURL := os.Getenv("DATABASE_URL")
	db, err = sql.Open("postgres", databaseURL) // Open the PostgreSQL connection
	if err != nil {
		log.Fatal("Failed to connect to the database:", err)
	}

	// Create tables if they don't exist
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

func main() {
	initDB()
	defer db.Close()

	r := gin.Default()

	// Serve HTML page for root ("/")
	r.LoadHTMLFiles("templates/index.html")
	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", nil)
	})

	r.Static("/assets", "./assets")

	// Get all tasks
	r.GET("/tasks", func(c *gin.Context) {
		var tasks []Task
		rows, err := db.Query("SELECT id, text, type FROM tasks")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to fetch tasks"})
			return
		}
		defer rows.Close()

		for rows.Next() {
			var task Task
			if err := rows.Scan(&task.ID, &task.Text, &task.Type); err != nil {
				log.Fatal(err)
			}
			tasks = append(tasks, task)
		}
		c.JSON(http.StatusOK, tasks)
	})

	// Create new task
	r.POST("/tasks", func(c *gin.Context) {
		var task Task
		if err := c.ShouldBindJSON(&task); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid data"})
			return
		}

		_, err := db.Exec("INSERT INTO tasks (text, type) VALUES ($1, $2)", task.Text, task.Type)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to save task"})
			return
		}

		c.JSON(http.StatusCreated, gin.H{"message": "Task saved successfully"})
	})

	// Delete a task
	r.DELETE("/tasks/:id", func(c *gin.Context) {
		id := c.Param("id")
		_, err := db.Exec("DELETE FROM tasks WHERE id = $1", id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to delete task"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Task deleted successfully"})
	})

	// Run the server
	r.Run(":8080")
}
