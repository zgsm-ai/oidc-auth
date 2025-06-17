package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/zgsm-ai/oidc-auth/internal/constants"
	"github.com/zgsm-ai/oidc-auth/internal/providers"
	"github.com/zgsm-ai/oidc-auth/internal/repository"
	"github.com/zgsm-ai/oidc-auth/pkg/log"
	"github.com/zgsm-ai/oidc-auth/pkg/response"
	"github.com/zgsm-ai/oidc-auth/pkg/utils"
)

const (
	defaultTimeout = 45 * time.Second
	shortTimeout   = 10 * time.Second
)

var (
	serverConfig Server
)

func SetServerConfig(config Server) {
	serverConfig = config
}

func getContextWithTimeout(timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), timeout)
}

func handleError(c *gin.Context, status int, err error) {
	log.Error(nil, "operation failed: %v", err)
	response.JSONError(c, status, err.Error())
}

func getEncryptedData(data any) (string, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("failed to marshal data: %w", err)
	}

	keyManager, err := utils.GetEncryptKeyManager()
	if err != nil {
		return "", fmt.Errorf("failed to get key manager: %w", err)
	}

	return keyManager.AESEncrypt(jsonData)
}

func getDecryptedData(encryptedData string, result any) error {
	keyManager, err := utils.GetEncryptKeyManager()
	if err != nil {
		return fmt.Errorf("failed to get key manager: %w", err)
	}

	decrypted, err := keyManager.AESDecrypt(encryptedData)
	if err != nil {
		return fmt.Errorf("failed to decrypt data: %w", err)
	}

	return json.Unmarshal(decrypted, result)
}

func bindAccount(c *gin.Context) {
	token, err := getTokenFromHeader(c)
	if err != nil {
		handleError(c, http.StatusBadRequest, err)
		return
	}

	tokenHash := utils.HashToken(token)
	oauthManager := providers.GetManager()
	provider := c.DefaultQuery("provider", "casdoor")
	providerInstance, err := oauthManager.GetProvider(provider)
	if err != nil {
		handleError(c, http.StatusInternalServerError, err)
		return
	}

	if serverConfig.BaseURL == "" {
		handleError(c, http.StatusInternalServerError, fmt.Errorf("base URL is not configured"))
		return
	}

	encryptedData, err := getEncryptedData(ParameterCarrier{
		TokenHash: tokenHash,
	})
	if err != nil {
		handleError(c, http.StatusInternalServerError, err)
		return
	}

	redirectURL := fmt.Sprintf("%s%s", serverConfig.BaseURL, constants.BindAccountCallbackPath)
	bindType := c.DefaultQuery("bindType", "")
	var bindParm string
	if bindType == "github" {
		bindParm = "&bindType=github"
	} else {
		bindParm = "&bindType=sms"
	}
	URL := providerInstance.GetAuthURL(encryptedData, redirectURL) + bindParm

	response.JSONSuccess(c, map[string]interface{}{
		"URL": URL,
	})
}

func bindAccountCallback(c *gin.Context) {
	code := c.DefaultQuery("code", "")
	if code == "" {
		handleError(c, http.StatusBadRequest, fmt.Errorf("code is required"))
		return
	}
	encryptedData := c.DefaultQuery("state", "")
	if encryptedData == "" {
		handleError(c, http.StatusBadRequest, fmt.Errorf("state is required"))
		return
	}
	var parameterCarrier ParameterCarrier
	if err := getDecryptedData(encryptedData, &parameterCarrier); err != nil {
		handleError(c, http.StatusInternalServerError, err)
		return
	}
	oauthManager := providers.GetManager()
	providerInstance, err := oauthManager.GetProvider("casdoor")
	if err != nil {
		handleError(c, http.StatusInternalServerError, err)
		return
	}
	ctx, cancel := getContextWithTimeout(defaultTimeout)
	defer cancel()

	parameterCarrier.Provider = "casdoor"
	userNew, err := GetUserByOauth(ctx, "plugin", code, &parameterCarrier)
	if err != nil {
		handleError(c, http.StatusInternalServerError, err)
		return
	}
	userOld, err := repository.GetDB().GetUserByDeviceConditions(ctx, map[string]any{
		"access_token_hash": parameterCarrier.TokenHash,
	})
	if err != nil || userOld == nil || userNew == nil {
		handleError(c, http.StatusInternalServerError, fmt.Errorf("user does not exist"))
		return
	}
	// Get a new user and first determine whether it exists in the database
	var userNewExist *repository.AuthUser
	ctx, cancel = getContextWithTimeout(defaultTimeout)
	defer cancel()
	if userOld.GithubID != "" {
		userNewExist, err = repository.GetDB().GetUserByField(ctx, "phone", userNew.Phone)
	} else if userOld.Phone != "" {
		userNewExist, err = repository.GetDB().GetUserByField(ctx, "github_id", userNew.GithubID)
	} else {
		// custom types are not considered
		handleError(c, http.StatusInternalServerError, fmt.Errorf("does not support custom account binding"))
		return
	}
	userMarge := userOld
	if userNewExist == nil {
		userNewExist = userNew
	} else {
		// delete one of the accounts
		if delNum, err := repository.GetDB().DeleteUserByField(ctx, constants.DBIndexField, userNewExist.ID); err != nil || delNum == 0 {
			handleError(c, http.StatusInternalServerError, fmt.Errorf("failed to delete old user, %w", err))
			return
		}
	}

	userMarge.Email = coalesceString(userOld.Email, userNew.Email)
	userMarge.Name = coalesceString(userOld.Name, userNew.Name)
	userMarge.Phone = coalesceString(userOld.Phone, userNew.Phone)
	userMarge.GithubID = coalesceString(userOld.GithubID, userNew.GithubID)
	userMarge.GithubName = coalesceString(userOld.GithubName, userNew.GithubName)
	userMarge.UpdatedAt = time.Now()

	if err := repository.GetDB().Upsert(ctx, userMarge, constants.DBIndexField, userMarge.ID); err != nil {
		handleError(c, http.StatusInternalServerError, fmt.Errorf("failed to update new user: %w", err))
		return
	}
	c.Redirect(http.StatusFound, providerInstance.GetEndpoint()+constants.LoginSuccessPath)
}

func userInfoHandler(c *gin.Context) {
	token, err := getTokenFromHeader(c)
	if err != nil {
		handleError(c, http.StatusBadRequest, err)
		return
	}

	tokenHash := utils.HashToken(token)
	ctx, cancel := getContextWithTimeout(shortTimeout)
	defer cancel()

	user, err := repository.GetDB().GetUserByDeviceConditions(ctx, map[string]any{
		"access_token_hash": tokenHash,
	})
	if err != nil || user == nil {
		handleError(c, http.StatusBadRequest, fmt.Errorf("user does not exist"))
		return
	}

	data := gin.H{
		"username":   user.Name,
		"uuid":       user.ID.String(),
		"email":      user.Email,
		"phone":      user.Phone,
		"githubID":   user.GithubID,
		"githubName": user.GithubName,
	}

	response.JSONSuccess(c, gin.H{
		"state": "success",
		"data":  data,
	})
}

func coalesceString(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
