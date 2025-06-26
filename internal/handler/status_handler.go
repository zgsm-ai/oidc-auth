package handler

import (
	"context"
	"fmt"
	"github.com/zgsm-ai/oidc-auth/pkg/errs"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/zgsm-ai/oidc-auth/internal/constants"
	"github.com/zgsm-ai/oidc-auth/internal/repository"
	"github.com/zgsm-ai/oidc-auth/pkg/response"
	"github.com/zgsm-ai/oidc-auth/pkg/utils"
)

// logoutHandler Log out by revoking the previous token.
func logoutHandler(c *gin.Context) {
	platform := c.DefaultQuery("platform", "")
	if platform == "plugin" {
		accessToken, err := getTokenFromHeader(c)
		if err != nil {
			response.JSONError(c, http.StatusBadRequest, err.Error())
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		user, index, err := utils.GetUserByTokenHash(ctx, accessToken, "access_token_hash")
		if err != nil {
			response.HandleError(c, http.StatusBadRequest, fmt.Errorf("%s, %s", errs.ErrQueryUserInfo, err))
			return
		}
		if user == nil || index == -1 {
			response.HandleError(c, http.StatusUnauthorized, errs.ErrInvalidToken)
			return
		}
		user.Devices[index].Status = constants.LoginStatusLoggedOffline
		user.Devices[index].RefreshTokenHash = ""
		user.Devices[index].RefreshToken = ""
		user.Devices[index].AccessTokenHash = ""
		user.Devices[index].AccessToken = ""
		user.UpdatedAt = time.Now()
		err = repository.GetDB().Upsert(ctx, user, constants.DBIndexField, user.ID)
		if err != nil {
			response.HandleError(c, http.StatusBadRequest, fmt.Errorf("%s, %s", errs.ErrUpdateUserInfo, err))
			return
		}
	}
	response.JSONSuccess(c, "", gin.H{
		"state":  c.DefaultQuery("state", ""),
		"status": constants.LoginStatusLoggedOffline,
	})
	return
}

// statusHandler Fetches the user's status, which is only possible with a valid token.
func statusHandler(c *gin.Context) {
	platform := c.DefaultQuery("platform", "")
	if platform != "plugin" {
		response.JSONError(c, http.StatusBadRequest, "device must be vscode plugin")
		return
	}
	accessToken, err := getTokenFromHeader(c)
	if err != nil {
		response.JSONError(c, http.StatusBadRequest, errs.ParmaNeedErr("access_token").Error())
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	user, index, err := utils.GetUserByTokenHash(ctx, accessToken, "access_token_hash")
	if user == nil || index == -1 {
		response.HandleError(c, http.StatusUnauthorized, errs.ErrInvalidToken)
		return
	}
	status := user.Devices[index].Status
	response.JSONSuccess(c, fmt.Sprintf("the user is %s", status), gin.H{
		"state":  c.DefaultQuery("state", ""),
		"status": status,
	})
}
