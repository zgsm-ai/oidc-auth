package response

import (
	"time"

	"github.com/gin-gonic/gin"
)

// JSONSuccess returns successful response
func JSONSuccess(c *gin.Context, data map[string]any) {
	data["success"] = true
	data["message"] = "success"
	response := gin.H(data)
	c.JSON(200, response)
}

// JSONError returns error response (basic version)
func JSONError(c *gin.Context, code int, message string) {
	c.JSON(code, gin.H{
		"success":   false,
		"message":   message,
		"timestamp": time.Now(),
	})
}
