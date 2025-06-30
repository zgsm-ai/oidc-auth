package handler

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/zgsm-ai/oidc-auth/internal/constants"
	"github.com/zgsm-ai/oidc-auth/internal/providers"
	"github.com/zgsm-ai/oidc-auth/internal/repository"
	"github.com/zgsm-ai/oidc-auth/pkg/errs"
	"github.com/zgsm-ai/oidc-auth/pkg/response"
)

type requestQuery struct {
	Provider      string `form:"provider"`
	State         string `form:"state" binding:"required"`
	MachineCode   string `form:"machine_code"`
	UriScheme     string `form:"uri_scheme"`
	PluginVersion string `form:"plugin_version"`
	VscodeVersion string `form:"vscode_version"`
}

func (r *requestQuery) validLoginParams(isPlugin bool) error {
	if isPlugin {
		if r.VscodeVersion == "" {
			return errs.ParmaNeedErr("vscode_version")
		}
		if r.MachineCode == "" {
			return errs.ParmaNeedErr("machine_code")
		}
	}
	return nil
}

// loginHandler The OAuth flow: Redirect to the login page, then back to a callback URL to get the token and user information
func (s *Server) loginHandler(c *gin.Context) {
	var queryParams requestQuery

	if err := c.ShouldBindQuery(&queryParams); err != nil {
		response.JSONError(c, http.StatusBadRequest, err.Error())
		return
	}
	isPlugin := c.DefaultQuery("platform", "") == "plugin" // vscode plugin login
	err := queryParams.validLoginParams(isPlugin)
	if err != nil {
		response.JSONError(c, http.StatusBadRequest, err.Error())
		return
	}
	provider := c.DefaultQuery("provider", "") // Get the OAuth provider, such as GitHub or Casdoor.
	if provider == "" {
		response.JSONError(c, http.StatusBadRequest, "please select a provider, such as casdoor.")
		return
	}
	oauthManager := providers.GetManager()
	// Due to cross-origin (CORS) issues, we are encrypting the required information to pass it to the next stage.
	encryptedData, err := getEncryptedData(ParameterCarrier{
		Provider:      provider,
		Platform:      c.DefaultQuery("platform", ""),
		MachineCode:   queryParams.MachineCode,
		VscodeVersion: queryParams.VscodeVersion,
		UriScheme:     queryParams.UriScheme,
		PluginVersion: queryParams.PluginVersion,
		State:         queryParams.State,
	})
	if err != nil {
		response.JSONError(c, http.StatusInternalServerError, fmt.Sprintf("failed to encrypt data, %s", err))
		return
	}
	providerInstance, err := oauthManager.GetProvider(provider)
	if providerInstance == nil || err != nil {
		response.JSONError(c, http.StatusBadRequest, "this login method is not supported, please choose SMS or GitHub.")
		return
	}
	authURL := providerInstance.GetAuthURL(encryptedData, s.BaseURL+constants.LoginCallbackURI)
	c.Redirect(http.StatusFound, authURL)
}

// callbackHandler Use the code to get the token and user info, and use the state to get the other parameters.
func (s *Server) callbackHandler(c *gin.Context) {
	code := c.DefaultQuery("code", "")
	encryptedData := c.DefaultQuery("state", "")
	if code == "" {
		response.JSONError(c, http.StatusBadRequest, errs.ParmaNeedErr("code").Error())
		return
	}
	if encryptedData == "" {
		response.JSONError(c, http.StatusInternalServerError, errs.ParmaNeedErr("state").Error())
		return
	}

	// Decrypt the required data using AES.
	var parameterCarrier ParameterCarrier
	if err := getDecryptedData(encryptedData, &parameterCarrier); err != nil {
		response.HandleError(c, http.StatusInternalServerError, fmt.Errorf("failed to decrypt data, %v", err))
		return
	}

	provider := parameterCarrier.Provider
	platform := parameterCarrier.Platform
	state := parameterCarrier.State
	if state == "" {
		response.HandleError(c, http.StatusInternalServerError, errs.ParmaNeedErr("state"))
		return
	}
	oauthManager := providers.GetManager()
	providerInstance, err := oauthManager.GetProvider(provider)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	userAlreadyExist, err := repository.GetDB().GetUserByDeviceConditions(ctx, map[string]any{
		"machine_code":   parameterCarrier.MachineCode,
		"vscode_version": parameterCarrier.VscodeVersion,
	})
	if err != nil {
		errMsg := fmt.Errorf("%s :%s", errs.ErrQueryUserInfo, err.Error())
		response.HandleError(c, http.StatusUnauthorized, errMsg)
		return
	}
	// If the mac and vs are the same, it can be determined that they are the same vs login.
	// This situation will squeeze out previous users.
	if userAlreadyExist != nil {
		index := findDeviceIndex(userAlreadyExist, parameterCarrier.MachineCode, parameterCarrier.VscodeVersion)
		if index == -1 {
			response.HandleError(c, http.StatusUnauthorized, errs.ErrQueryUserInfo)
			return
		} else {
			// There will be no concurrent logins on the same device
			userAlreadyExist.Devices[index].Status = constants.LoginStatusLoggedOffline
			userAlreadyExist.Devices[index].AccessTokenHash = ""
			userAlreadyExist.Devices[index].AccessToken = ""
			userAlreadyExist.Devices[index].RefreshTokenHash = ""
			userAlreadyExist.Devices[index].RefreshToken = ""
			userAlreadyExist.Devices[index].UpdatedAt = time.Now()
			userAlreadyExist.UpdatedAt = time.Now()
			err := repository.GetDB().Upsert(ctx, userAlreadyExist, constants.DBIndexField, userAlreadyExist.ID)
			if err != nil {
				errMsg := fmt.Errorf("failed to update login user information: %v", err) // TODO
				response.HandleError(c, http.StatusInternalServerError, errMsg)
				return
			}
		}
	}
	// Use the code to get the token and user info.
	user, err := GetUserByOauth(ctx, platform, code, &parameterCarrier)
	if err != nil {
		response.HandleError(c, http.StatusInternalServerError, fmt.Errorf("%s: %v", errs.ErrQueryUserInfo, err))
		return
	}
	if user == nil || len(user.Devices) == 0 {
		response.HandleError(c, http.StatusUnauthorized, errs.ErrInvalidToken)
		return
	}
	user.Devices[0].State = state
	err = providerInstance.Update(ctx, user)
	if err != nil {
		response.HandleError(c, http.StatusInternalServerError, fmt.Errorf("%s: %v", errs.ErrUpdateUserInfo, err))
		return
	}
	c.Redirect(http.StatusFound, providerInstance.GetEndpoint(false)+constants.LoginSuccessPath)
}

// GetUserByOauth Use the code to exchange for a token and generate user information
func GetUserByOauth(ctx context.Context, typ, code string, parm *ParameterCarrier) (*repository.AuthUser, error) {
	provider := parm.Provider
	oauthManager := providers.GetManager()
	providerInstance, err := oauthManager.GetProvider(provider)
	if err != nil {
		return nil, err
	}
	token, err := providerInstance.ExchangeToken(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}
	user, userErr := providerInstance.GetUserInfo(ctx, token.AccessToken)
	if userErr != nil {
		return nil, fmt.Errorf("%s: %v", errs.ErrQueryUserInfo, userErr)
	}
	if typ == "plugin" {
		mac := parm.MachineCode
		uScheme := parm.UriScheme
		vsVersion := parm.VscodeVersion
		pVersion := parm.PluginVersion

		var tokenProvider, refreshToken, accessToken string
		if provider == "casdoor" {
			refreshToken = token.RefreshToken
			accessToken = token.AccessToken
			tokenProvider = "custom" // Use a token generated by a provider (custom) or a token generated by the service
		}
		if user.ID == uuid.Nil {
			user.ID = uuid.New()
		}
		user.Devices = append(user.Devices, repository.Device{
			ID:            uuid.New(),
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
			MachineCode:   mac,
			UriScheme:     uScheme,
			VSCodeVersion: vsVersion,
			PluginVersion: pVersion,
			RefreshToken:  refreshToken,
			AccessToken:   accessToken,
			Provider:      provider,
			Platform:      "plugin",
			Status:        constants.LoginStatusLoggedOut,
			TokenProvider: tokenProvider,
		})
	}
	return user, nil
}
