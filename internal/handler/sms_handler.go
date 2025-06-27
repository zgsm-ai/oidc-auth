package handler

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/zgsm-ai/oidc-auth/internal/service"
	"github.com/zgsm-ai/oidc-auth/pkg/log"
	"github.com/zgsm-ai/oidc-auth/pkg/response"
)

type ResponseBody struct {
	Status string `json:"status"`
	Msg    string `json:"msg,omitempty"`
}

func (s *Server) SMSHandler(c *gin.Context) {
	contentType := c.ContentType()

	var phoneNumber string
	var messageContent string
	var data map[string]any

	if strings.HasPrefix(contentType, "application/x-www-form-urlencoded") ||
		strings.HasPrefix(contentType, "multipart/form-data") {

		err := c.Request.ParseForm()
		if err != nil {
			log.Error(c, "Error parsing form: %v", err)
			c.JSON(http.StatusBadRequest, ResponseBody{Status: "error", Msg: "failed to parse form data"})
			return
		}
		phoneNumber = c.PostForm("phoneNumber")
		messageContent = c.PostForm("code")
	} else {
		log.Error(c, "unsupported Content-Type: %s", contentType)
		response.JSONError(c, http.StatusUnsupportedMediaType, "unsupported Content-Type")
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
		response.JSONError(c, http.StatusBadRequest, errmsg)
		return
	}
	SMSCfg := service.GetSMSCfg(nil)
	if SMSCfg.EnabledTest {
		log.Info(c, "processed request to send SMS to: %s, content: %s", phoneNumber, messageContent)
		log.Info(c, "simulating SMS sent to %s with content: %s", phoneNumber, messageContent)
	} else {
		code, err := service.GetLoginCode(SMSCfg.ClientID, SMSCfg.ClientSecret)
		if err != nil {
			errmsg := fmt.Sprintf("Error getting sms code: %v", err)
			log.Error(c, "Error: %s received data: %v", errmsg)
			response.JSONError(c, http.StatusBadRequest, errmsg)
			return
		}
		token, err := service.GetJWTToken(code, SMSCfg.ClientID, s.HTTPClient)
		if err != nil {
			errmsg := fmt.Sprintf("Error getting sms token: %v", err)
			log.Error(c, "Error: %s Received data: %v", errmsg)
			response.JSONError(c, http.StatusBadRequest, errmsg)
			return
		}
		_, err = service.SendSMS(token, phoneNumber, messageContent)
		if err != nil {
			errmsg := fmt.Sprintf("Error getting sms token: %v", err)
			log.Error(c, "Error: %s Received data: %v", errmsg)
			response.JSONError(c, http.StatusBadRequest, errmsg)
			return
		}
	}
	c.JSON(http.StatusOK, ResponseBody{Status: "ok", Msg: "simulated SMS sent successfully"})
}
