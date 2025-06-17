package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/zgsm-ai/oidc-auth/internal/constants"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/zgsm-ai/oidc-auth/internal/repository"
	"github.com/zgsm-ai/oidc-auth/pkg/utils"
)

type CasdoorFactory struct{}

type casdoorConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Endpoint     string
	Scopes       []string
}

type CasdoorProvider struct {
	config     *casdoorConfig
	httpClient *http.Client
}

func NewCasdoorFactory() *CasdoorFactory {
	return &CasdoorFactory{}
}

func (s *CasdoorFactory) GetName() string {
	return "casdoor"
}

func (f *CasdoorFactory) CreateProvider(config *ProviderConfig) OAuthProvider {
	return NewCasdoorProvider(config)
}

func NewCasdoorProvider(config *ProviderConfig) *CasdoorProvider {
	return &CasdoorProvider{
		httpClient: &http.Client{},
		config: &casdoorConfig{
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			RedirectURL:  config.RedirectURL,
			Endpoint:     config.Endpoint,
		},
	}
}

func (s *CasdoorProvider) GetName() string {
	return "casdoor"
}

func (s *CasdoorProvider) ExchangeToken(ctx context.Context, code string) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("code", code)
	data.Set("grant_type", "authorization_code")
	data.Set("client_secret", s.config.ClientSecret)
	data.Set("client_id", s.config.ClientID)

	getTokenURL := s.config.Endpoint + constants.CasdoorTokenURI
	req, err := http.NewRequest(http.MethodPost, getTokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpClient := &http.Client{}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to request token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get token, status: %d", resp.StatusCode)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}
	return &tokenResp, nil
}

func (s *CasdoorProvider) Update(ctx context.Context, data *repository.AuthUser) error {
	if len(data.Devices) != 1 {
		return fmt.Errorf("invalid input: data must contain exactly one device")
	}
	var existingUser *repository.AuthUser
	var err error
	if data.GithubID != "" {
		existingUser, err = repository.GetDB().GetUserByField(ctx, "github_id", data.GithubID)
		if err != nil {
			return fmt.Errorf("failed to get user: %w", err)
		}
	} else if data.Phone != "" {
		existingUser, err = repository.GetDB().GetUserByField(ctx, "phone", data.Phone)
		if err != nil {
			return fmt.Errorf("failed to get user: %w", err)
		}
	} else if data.Email != "" {
		existingUser, err = repository.GetDB().GetUserByField(ctx, "email", data.Email)
		if err != nil {
			return fmt.Errorf("failed to get user: %w", err)
		}
	} else {
		return fmt.Errorf("user must have either github_id, phone, or email")
	}

	if existingUser == nil {
		if data.UserCode == "" {
			data.UserCode, err = utils.GenerateRandomString(16)
			if err != nil {
				return err
			}
		}
		if data.Devices[0].DeviceCode == "" {
			data.Devices[0].DeviceCode, err = utils.GenerateRandomString(16)
			if err != nil {
				return err
			}
		}
		if data.GithubID != "" {
			err = repository.GetDB().Upsert(ctx, data, "github_id", data.GithubID)
		} else if data.Phone != "" {
			err = repository.GetDB().Upsert(ctx, data, "phone", data.Phone)
		} else if data.Email != "" {
			// custom login
			data.EmployeeNumber = data.Name
			err = repository.GetDB().Upsert(ctx, data, "email", data.Email)
		}
		if err != nil {
			return fmt.Errorf("failed to create user: %w", err)
		}
		return nil
	}
	existingUser.GithubName = data.GithubName
	existingUser.Name = data.Name
	existingUser.Email = data.Email
	existingUser.Location = data.Location
	existingUser.Company = data.Company
	existingUser.Phone = data.Phone
	existingUser.Vip = data.Vip
	existingUser.EmployeeNumber = data.EmployeeNumber

	newDevice := data.Devices[0]
	newDevice.UpdatedAt = time.Now()

	if existingUser.ID == uuid.Nil {
		existingUser.ID = uuid.New()
		existingUser.CreatedAt = time.Now()
		existingUser.UpdatedAt = time.Now()
	}

	if newDevice.ID == uuid.Nil {
		newDevice.ID = uuid.New()
		newDevice.CreatedAt = time.Now()
		newDevice.UpdatedAt = time.Now()
	}

	deviceFound := false
	for i, device := range existingUser.Devices {
		if device.MachineCode == newDevice.MachineCode && device.VSCodeVersion == newDevice.VSCodeVersion {
			newDevice.CreatedAt = device.CreatedAt

			if newDevice.DeviceCode == "" {
				newDevice.DeviceCode = existingUser.Devices[i].DeviceCode
			}
			if existingUser.Devices[i].ID.String() != "" {
				newDevice.ID = existingUser.Devices[i].ID
			}
			existingUser.Devices[i] = newDevice
			deviceFound = true
			break
		}
	}
	if !deviceFound {
		newDevice.DeviceCode, err = utils.GenerateRandomString(16)
		if err != nil {
			return err
		}
		existingUser.Devices = append(existingUser.Devices, newDevice)
	}

	if data.GithubID != "" {
		err = repository.GetDB().Upsert(ctx, *existingUser, "github_id", existingUser.GithubID)
		if err != nil {
			return fmt.Errorf("failed to get user: %w", err)
		}
	} else if data.Phone != "" {
		err = repository.GetDB().Upsert(ctx, *existingUser, "phone", existingUser.Phone)
		if err != nil {
			return fmt.Errorf("failed to get user: %w", err)
		}
	} else if data.Email != "" {
		existingUser, err = repository.GetDB().GetUserByField(ctx, "email", data.Email)
		if err != nil {
			return fmt.Errorf("failed to get user: %w", err)
		}
	} else {
		return fmt.Errorf("user must have either github_id, phone, or email")
	}
	return nil
}

func (s *CasdoorProvider) GetUserInfo(ctx context.Context, accessToken string) (*repository.AuthUser, error) {
	payload, err := utils.DecodeJWTPayloadUnverified(accessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to decode AESEncrypt payload: %w", err)
	}
	githubID, _ := payload.CustomClaims["github"].(string)
	name, _ := payload.CustomClaims["name"].(string)
	var githubName string
	if githubID != "" {
		githubName = payload.CustomClaims["displayName"].(string)
	}
	user := &repository.AuthUser{
		Phone:      payload.CustomClaims["phone"].(string),
		GithubID:   githubID,
		Email:      payload.CustomClaims["email"].(string),
		Name:       name,
		GithubName: githubName,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	return user, nil
}

func (s *CasdoorProvider) RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("refresh_token", refreshToken)
	data.Set("grant_type", "refresh_token")
	data.Set("client_secret", s.config.ClientSecret)
	data.Set("client_id", s.config.ClientID)
	refreshTokenURL := s.config.Endpoint + constants.CasdoorRefreshTokenURI
	req, err := http.NewRequest(http.MethodPost, refreshTokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get token, status: %d", resp.StatusCode)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode refresh token response: %w", err)
	}

	return &tokenResp, nil
}

func (s *CasdoorProvider) GetAuthURL(state, redirectURL string) string {
	if redirectURL == "" {
		redirectURL = url.QueryEscape(s.config.RedirectURL)
	}
	return s.config.Endpoint + constants.CasdoorAuthURI + "?client_id=" + s.config.ClientID + "&state=" + state + "&redirect_uri=" + redirectURL + "&response_type=code"
}

func (s *CasdoorProvider) GetEndpoint() string {
	return s.config.Endpoint
}

func (s *CasdoorProvider) ValidateToken(ctx context.Context, accessToken string) error {
	return fmt.Errorf("oauth oauth does not support refresh token")
}
