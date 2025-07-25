package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/zgsm-ai/oidc-auth/pkg/errs"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zgsm-ai/oidc-auth/internal/constants"
	"github.com/zgsm-ai/oidc-auth/internal/providers"
	"github.com/zgsm-ai/oidc-auth/internal/repository"
	"github.com/zgsm-ai/oidc-auth/internal/service"
	github "github.com/zgsm-ai/oidc-auth/internal/sync"
	"github.com/zgsm-ai/oidc-auth/pkg/response"
	"github.com/zgsm-ai/oidc-auth/pkg/utils"
)

const (
	defaultTimeout = 45 * time.Second
	shortTimeout   = 10 * time.Second
)

func getContextWithTimeout(timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), timeout)
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

func (s *Server) bindAccount(c *gin.Context) {
	token, err := getTokenFromHeader(c)
	if err != nil {
		response.HandleError(c, http.StatusBadRequest, errs.ErrBadRequestParam, err)
		return
	}

	tokenHash := utils.HashToken(token)
	oauthManager := providers.GetManager()
	provider := c.DefaultQuery("provider", "casdoor")
	providerInstance, err := oauthManager.GetProvider(provider)
	if err != nil {
		response.HandleError(c, http.StatusInternalServerError, errs.ErrBadRequestParam, err)
		return
	}

	if s.BaseURL == "" {
		response.HandleError(c, http.StatusInternalServerError, errs.ErrBadRequestParam,
			fmt.Errorf("base URL is not configured"))
		return
	}

	encryptedData, err := getEncryptedData(ParameterCarrier{
		TokenHash: tokenHash,
	})
	if err != nil {
		response.HandleError(c, http.StatusInternalServerError, errs.ErrDataEncryption, err)
		return
	}

	redirectURL := fmt.Sprintf("%s%s", s.BaseURL, constants.BindAccountCallbackURI)
	bindType := c.DefaultQuery("bindType", "")
	var bindParm string
	if bindType == "github" {
		bindParm = "&bindType=github"
	} else {
		bindParm = "&bindType=sms"
	}
	url := providerInstance.GetAuthURL(encryptedData, redirectURL) + bindParm

	response.JSONSuccess(c, "", map[string]interface{}{
		"state": c.DefaultQuery("state", ""),
		"url":   url,
	})
}

func (s *Server) bindAccountCallback(c *gin.Context) {
	code := c.DefaultQuery("code", "")
	if code == "" {
		response.HandleError(c, http.StatusBadRequest, errs.ErrBadRequestParam,
			errs.ParamNeedErr("code"))
		return
	}
	encryptedData := c.DefaultQuery("state", "")
	if encryptedData == "" {
		response.HandleError(c, http.StatusBadRequest, errs.ErrBadRequestParam,
			errs.ParamNeedErr("state"))
		return
	}
	var parameterCarrier ParameterCarrier
	if err := getDecryptedData(encryptedData, &parameterCarrier); err != nil {
		response.HandleError(c, http.StatusInternalServerError, errs.ErrDataDecryption, err)
		return
	}
	oauthManager := providers.GetManager()
	providerInstance, err := oauthManager.GetProvider("casdoor")
	if err != nil {
		response.HandleError(c, http.StatusInternalServerError, errs.ErrBadRequestParam, err)
		return
	}
	ctx, cancel := getContextWithTimeout(defaultTimeout)
	defer cancel()

	parameterCarrier.Provider = "casdoor"
	userNew, err := GetUserByOauth(ctx, "plugin", code, &parameterCarrier)
	if err != nil {
		response.HandleError(c, http.StatusInternalServerError, errs.ErrUserNotFound, err)
		return
	}
	userOld, err := repository.GetDB().GetUserByDeviceConditions(ctx, map[string]any{
		"access_token_hash": parameterCarrier.TokenHash,
	})
	if err != nil || userOld == nil || userNew == nil {
		response.HandleError(c, http.StatusUnauthorized, errs.ErrUserNotFound, errs.ErrInfoQueryUserInfo)
		return
	}
	// The already bound one cannot be bound again
	if userOld.GithubID != "" && userOld.Phone != "" {
		response.HandleError(c, http.StatusConflict, errs.ErrUpdateInfo, fmt.Errorf("this account has already been bound"))
		return
	}
	var useroldToken string
	for _, device := range userOld.Devices {
		if device.AccessTokenHash == parameterCarrier.TokenHash {
			useroldToken = device.AccessToken
			break
		}
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
		response.HandleError(c, http.StatusInternalServerError, errs.ErrTokenInvalid,
			fmt.Errorf("does not support custom account binding"))
		return
	}
	userMarge := userOld
	if userNewExist != nil {
		if userNewExist.GithubID != "" && userNewExist.Phone != "" {
			response.HandleError(c, http.StatusConflict, errs.ErrUpdateInfo, fmt.Errorf("this account has already been bound"))
			return
		}
	}
	resp, err := service.MergeByCasdoor(providerInstance, useroldToken, userNew.Devices[0].AccessToken, s.HTTPClient)
	if err != nil {
		response.HandleError(c, http.StatusInternalServerError, errs.ErrBindAccount,
			fmt.Errorf("account linking failed, %w", err))
		return
	}
	if resp.Status != "ok" {
		response.HandleError(c, http.StatusInternalServerError, errs.ErrBindAccount,
			fmt.Errorf("failed to merge account"))
		return
	}
	if userNewExist != nil {
		// delete one of the accounts
		if delNum, err := repository.GetDB().DeleteUserByField(ctx, constants.DBIndexField, userNewExist.ID); err != nil || delNum == 0 {
			response.HandleError(c, http.StatusInternalServerError, errs.ErrBindAccount,
				fmt.Errorf("failed to delete old user, %w", err))
			return
		}
	}
	userMarge.Email = coalesceString(userOld.Email, userNew.Email)
	userMarge.Phone = coalesceString(userOld.Phone, userNew.Phone)
	userMarge.GithubID = coalesceString(userOld.GithubID, userNew.GithubID)
	userMarge.GithubName = coalesceString(userOld.GithubName, userNew.GithubName)
	userMarge.UpdatedAt = time.Now()
	if userMarge.GithubName != "" {
		userMarge.Name = userMarge.GithubName
	} else {
		userMarge.Name = coalesceString(userOld.Name, userNew.Name)
	}

	if err := repository.GetDB().Upsert(ctx, userMarge, constants.DBIndexField, userMarge.ID); err != nil {
		response.HandleError(c, http.StatusInternalServerError, errs.ErrUpdateInfo,
			fmt.Errorf("%s: %w", errs.ErrInfoUpdateUserInfo, err))
		return
	}
	url := providerInstance.GetEndpoint(false) + constants.BindAccountBindURI + "?state=" + parameterCarrier.TokenHash
	url = url + "&bind=true"
	c.Redirect(http.StatusFound, url)
}

func (s *Server) userInfoHandler(c *gin.Context) {
	token, err := getTokenFromHeader(c)
	if err != nil {
		response.HandleError(c, http.StatusBadRequest, errs.ErrBadRequestParam, err)
		return
	}

	tokenHash := utils.HashToken(token)
	ctx, cancel := getContextWithTimeout(shortTimeout)
	defer cancel()

	user, err := repository.GetDB().GetUserByDeviceConditions(ctx, map[string]any{
		"access_token_hash": tokenHash,
	})
	if err != nil || user == nil {
		response.HandleError(c, http.StatusBadRequest, errs.ErrTokenInvalid, errs.ErrInfoInvalidToken)
		return
	}

	isStar := true
	starProject := user.GithubStar

	project := fmt.Sprintf("%s.%s", github.Owner, github.Repo)
	if starProject == "" || starProject != project {
		isStar = false
	}

	data := gin.H{
		"state":      c.DefaultQuery("state", ""),
		"username":   user.Name,
		"uuid":       user.ID.String(),
		"email":      user.Email,
		"phone":      user.Phone,
		"githubID":   user.GithubID,
		"githubName": user.GithubName,
		"isPrivate":  s.IsPrivate,
		"isStar":     isStar,
	}

	response.JSONSuccess(c, "", data)
}

func coalesceString(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
