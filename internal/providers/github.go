package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/zgsm-ai/oidc-auth/internal/constants"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/zgsm-ai/oidc-auth/internal/repository"
	"github.com/zgsm-ai/oidc-auth/pkg/utils"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

type GithubFactory struct{}

func NewGithubFactory() *GithubFactory {
	return &GithubFactory{}
}

func (f *GithubFactory) CreateProvider(config *ProviderConfig) OAuthProvider {
	return NewGithubProvider(config)
}

func (f *GithubFactory) GetName() string {
	return "github"
}

type GithubProvider struct {
	config     *oauth2.Config
	httpClient *http.Client
}

type GitHubUserResponse struct {
	ID        int    `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
	Company   string `json:"company"`
	Location  string `json:"location"`
	Bio       string `json:"bio"`
}

func NewGithubProvider(config *ProviderConfig) *GithubProvider {
	oauth2Config := &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.RedirectURL,
		Endpoint:     github.Endpoint,
	}

	if len(oauth2Config.Scopes) == 0 {
		oauth2Config.Scopes = []string{"user:email"}
	}

	httpClient := &http.Client{}

	return &GithubProvider{
		config:     oauth2Config,
		httpClient: httpClient,
	}
}

func (p *GithubProvider) GetName() string {
	return "github"
}

func (p *GithubProvider) GetIndexName() string {
	return "name"
}

func (p *GithubProvider) ExchangeToken(ctx context.Context, code string) (*TokenResponse, error) {
	p.httpClient = &http.Client{}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, p.httpClient)

	token, err := p.config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange token: %w", err)
	}

	response := &TokenResponse{
		AccessToken:  token.AccessToken,
		TokenType:    token.TokenType,
		RefreshToken: token.RefreshToken,
	}

	if !token.Expiry.IsZero() {
		response.ExpiresAt = token.Expiry
		response.ExpiresIn = int64(time.Until(token.Expiry).Seconds())
	}

	return response, nil
}

func (p *GithubProvider) Update(ctx context.Context, data *repository.AuthUser) error {
	if len(data.Devices) != 1 {
		return fmt.Errorf("invalid input: data must contain exactly one device")
	}

	existingUser, err := repository.GetDB().GetUserByField(ctx, "github_id", data.GithubID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
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
		err = repository.GetDB().Upsert(ctx, data, "github_id", data.GithubID)
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

	newDevice := data.Devices[0]
	newDevice.UpdatedAt = time.Now()

	if newDevice.ID == uuid.Nil {
		newDevice.ID = uuid.New()
		newDevice.CreatedAt = time.Now()
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

	err = repository.GetDB().Upsert(ctx, *existingUser, "github_id", existingUser.GithubID)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}

func (p *GithubProvider) GetUserInfo(ctx context.Context, accessToken string) (*repository.AuthUser, error) {
	p.httpClient = &http.Client{}
	token := &oauth2.Token{AccessToken: accessToken}
	client := p.config.Client(context.WithValue(ctx, oauth2.HTTPClient, p.httpClient), token)

	resp, err := client.Get(constants.GithubUserAPIURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get user info, status: %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	var userResp GitHubUserResponse
	if err := json.NewDecoder(resp.Body).Decode(&userResp); err != nil {
		return nil, fmt.Errorf("failed to decode user info response: %w", err)
	}

	return &repository.AuthUser{
		GithubName: userResp.Login,
		GithubID:   strconv.Itoa(userResp.ID),
		Email:      userResp.Email,
		Location:   userResp.Location,
		Company:    userResp.Company,
		Name:       userResp.Login,
	}, nil
}

func (p *GithubProvider) RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	return nil, fmt.Errorf("oauth oauth does not support refresh token")
}

func (p *GithubProvider) GetAuthURL(state, redirectURL string) string {
	return p.config.AuthCodeURL(state)
}

func (p *GithubProvider) GetEndpoint() string {
	return ""
}

func (p *GithubProvider) ValidateToken(ctx context.Context, accessToken string) error {
	_, err := p.GetUserInfo(ctx, accessToken)
	return err
}
