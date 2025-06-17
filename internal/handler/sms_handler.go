package handler

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/zgsm-ai/oidc-auth/pkg/log"
)

type ResponseBody struct {
	Status string `json:"status"`
	Msg    string `json:"msg,omitempty"`
}

func SMSHandler(c *gin.Context) {
	contentType := c.ContentType()

	var phoneNumber string
	var messageContent string
	var data map[string]any

	if strings.HasPrefix(contentType, "application/x-www-form-urlencoded") ||
		strings.HasPrefix(contentType, "multipart/form-data") {

		err := c.Request.ParseForm()
		if err != nil {
			log.Error(c, "Error parsing form: %v", err)
			c.JSON(http.StatusBadRequest, ResponseBody{Status: "error", Msg: "Failed to parse form data"})
			return
		}
		phoneNumber = c.PostForm("phoneNumber")
		messageContent = c.PostForm("code")
	} else {
		log.Error(c, "Unsupported Content-Type: %s", contentType)
		c.JSON(http.StatusUnsupportedMediaType, ResponseBody{
			Status: "error",
			Msg:    fmt.Sprintf("Unsupported Content-Type: %s. Expected form data or JSON.", contentType),
		})
		return
	}
	if phoneNumber == "" || messageContent == "" {
		errmsg := "Missing required fields. "
		if phoneNumber == "" {
			errmsg += "Expected 'phoneNumber' (from form) or 'receiver' (from JSON). "
		}
		if messageContent == "" {
			errmsg += "Expected 'code' (from form) or 'content' (from JSON). "
		}
		log.Error(c, "Error: %s Received data: %v", errmsg, data)
		c.JSON(http.StatusBadRequest, ResponseBody{Status: "error", Msg: strings.TrimSpace(errmsg)})
		return
	}

	log.Info(c, "Processed request to send SMS to: %s, content: %s", phoneNumber, messageContent)
	log.Info(c, "Simulating SMS sent to %s with content: %s", phoneNumber, messageContent)

	c.JSON(http.StatusOK, ResponseBody{Status: "ok", Msg: "Simulated SMS sent successfully"})
}
