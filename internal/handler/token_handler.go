package handler

import (
	"context"
	"fmt"
	"github.com/zgsm-ai/oidc-auth/pkg/errs"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/zgsm-ai/oidc-auth/internal/constants"
	"github.com/zgsm-ai/oidc-auth/internal/providers"
	"github.com/zgsm-ai/oidc-auth/internal/repository"
	"github.com/zgsm-ai/oidc-auth/pkg/response"
	"github.com/zgsm-ai/oidc-auth/pkg/utils"
)

// tokenHandler handles token requests (return new refresh_token/access_token by refresh token)
func tokenHandler(c *gin.Context) {
	var query requestQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		response.JSONError(c, http.StatusBadRequest, err.Error())
		return
	}
	if query.MachineCode != "" && query.VscodeVersion == "" {
		response.JSONError(c, http.StatusBadRequest, errs.ParmaNeedErr("machine_code or vscode_version").Error())
		return
	}
	// if MachineCode is provided, get the token for the first time
	// the account should have been pre-registered.
	if query.MachineCode != "" {
		tokenPair, code, err := firstGetToken(query.MachineCode, query.VscodeVersion)
		if err != nil {
			response.JSONError(c, code, err.Error())
			return
		}
		if tokenPair == nil {
			response.JSONError(c, http.StatusInternalServerError, errs.ErrGenerateToken.Error())
			return
		}
		response.JSONSuccess(c, "", gin.H{
			"access_token":  tokenPair.AccessToken,
			"refresh_token": tokenPair.RefreshToken,
			"state":         c.DefaultQuery("state", ""),
		})
		return
	}
	refreshToken, err := getTokenFromHeader(c)
	if err != nil {
		response.JSONError(c, http.StatusUnauthorized, err.Error())
		return
	}
	tokenPair, code, err := tokenRefresh(refreshToken)
	if err != nil {
		response.JSONError(c, code, err.Error())
		return
	}
	if tokenPair == nil {
		response.JSONError(c, http.StatusInternalServerError, errs.ErrGenerateToken.Error())
		return
	}
	response.JSONSuccess(c, "", gin.H{
		"access_token":  tokenPair.AccessToken,
		"refresh_token": tokenPair.RefreshToken,
		"state":         c.DefaultQuery("state", ""),
	})
}

func firstGetToken(machineCode, vscodeVersion string) (*utils.TokenPair, int, error) {
	if vscodeVersion == "" {
		return nil, http.StatusUnauthorized, errs.ParmaNeedErr("vscode_version")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	db := repository.GetDB()
	user, err := db.GetUserByDeviceConditions(ctx, map[string]any{
		"machine_code":   machineCode,
		"vscode_version": vscodeVersion,
		"status":         constants.LoginStatusLoggedOut,
	})
	if err != nil {
		return nil, http.StatusUnauthorized, errs.ErrQueryUserInfo
	}
	if user == nil {
		return nil, http.StatusUnauthorized, errs.ErrInvalidToken
	}

	index := findDeviceIndex(user, machineCode, vscodeVersion)
	if index == -1 {
		return nil, http.StatusUnauthorized, errs.ErrInvalidToken
	}

	tokenPair, err := generateTokenPair(ctx, user, index)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	user.Devices[index].Status = constants.LoginStatusLoggedIn
	if err := updateUserAndSave(ctx, user, index, tokenPair); err != nil {
		return nil, http.StatusInternalServerError, err
	}

	return &utils.TokenPair{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
	}, http.StatusOK, nil
}

func tokenRefresh(refreshToken string) (*utils.TokenPair, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	user, index, err := utils.GetUserByTokenHash(ctx, refreshToken, "refresh_token_hash")
	if err != nil {
		return nil, http.StatusUnauthorized, err
	}
	if user == nil {
		return nil, http.StatusUnauthorized, errs.ErrInvalidToken
	}

	tokenPair, err := generateTokenPair(ctx, user, index)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	if err := updateUserAndSave(ctx, user, index, tokenPair); err != nil {
		return nil, http.StatusInternalServerError, err
	}

	return &utils.TokenPair{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
	}, http.StatusOK, nil
}

func generateTokenPair(ctx context.Context, user *repository.AuthUser, index int) (*utils.TokenPair, error) {
	if user.Devices[index].TokenProvider == "custom" {
		return GenerateTokenPairByCustom(ctx, user, index)
	}

	tokenPair, err := utils.GenerateTokenPairByUser(user, index)
	if err != nil || tokenPair == nil {
		return nil, fmt.Errorf("%s, %v", errs.ErrGenerateToken, err)
	}
	return tokenPair, nil
}

func findDeviceIndex(user *repository.AuthUser, machineCode, vscodeVersion string) int {
	for i, device := range user.Devices {
		if device.MachineCode == machineCode && device.VSCodeVersion == vscodeVersion {
			user.Devices[i].UpdatedAt = time.Now()
			return i
		}
	}
	return -1
}

func updateUserAndSave(ctx context.Context, user *repository.AuthUser, index int, tokenPair *utils.TokenPair) error {
	updateUserInfoMid(user, index, tokenPair)
	return repository.GetDB().Upsert(ctx, user, constants.DBIndexField, user.ID)
}

func updateUserInfoMid(user *repository.AuthUser, index int, tokenPair *utils.TokenPair) {
	accessTokenNew := tokenPair.AccessToken
	refreshTokenNew := tokenPair.RefreshToken
	refreshTokenHash := utils.HashToken(refreshTokenNew)
	accessTokenHash := utils.HashToken(accessTokenNew)
	user.UpdatedAt = time.Now()
	user.AccessTime = time.Now()
	user.Devices[index].UpdatedAt = time.Now()
	user.Devices[index].AccessToken = accessTokenNew
	user.Devices[index].RefreshToken = refreshTokenNew
	user.Devices[index].AccessTokenHash = accessTokenHash
	user.Devices[index].RefreshTokenHash = refreshTokenHash
}

func getTokenByHash(c *gin.Context) {
	accessTokenHash, err := getTokenFromHeader(c)
	if err != nil {
		response.JSONError(c, http.StatusUnauthorized, errs.ParmaNeedErr("token").Error())
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tokenPair, err := utils.GetTokenByTokenHash(ctx, accessTokenHash)
	if err != nil {
		response.JSONError(c, http.StatusUnauthorized, fmt.Sprintf("%s, %s", errs.ErrQueryUserInfo, err.Error()))
		return
	}
	response.JSONSuccess(c, "", gin.H{
		"state":        c.DefaultQuery("state", ""),
		"access_token": tokenPair.AccessToken,
	})
}

func getTokenFromHeader(c *gin.Context) (string, error) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return "", errs.ParmaNeedErr("Authorization")
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) == 1 {
		return parts[0], nil
	}
	if !(len(parts) == 2 && parts[0] == "Bearer") {
		return "", errs.ParmaNeedErr("Bearer")
	}

	tokenString := parts[1]
	return tokenString, nil
}

func GenerateTokenPairByCustom(ctx context.Context, user *repository.AuthUser, index int) (*utils.TokenPair, error) {
	refreshToken := user.Devices[index].RefreshToken
	provider := user.Devices[index].Provider
	oauthManager := providers.GetManager()
	providerInstance, err := oauthManager.GetProvider(provider)
	if err != nil {
		return nil, err
	}
	token, err := providerInstance.RefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, err
	}
	return &utils.TokenPair{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}, nil
}
