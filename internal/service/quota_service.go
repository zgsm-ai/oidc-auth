package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/zgsm-ai/oidc-auth/internal/config"
	"github.com/zgsm-ai/oidc-auth/internal/constants"
	"github.com/zgsm-ai/oidc-auth/pkg/log"
)

type QuotaMergeRequest struct {
	MainUserID  string `json:"main_user_id" validate:"required,uuid"`  // 主用户ID（保留用户）
	OtherUserID string `json:"other_user_id" validate:"required,uuid"` // 其他用户ID（被删除用户）
}

type QuotaMergeResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Data    struct {
		MergedQuota int64 `json:"merged_quota"`
	} `json:"data"`
}

var (
	quotaConfig *config.QuotaConfig
	quotaOnce   sync.Once
)

func InitQuotaService(cfg *config.QuotaConfig) {
	quotaOnce.Do(func() {
		quotaConfig = cfg
		if quotaConfig != nil {
			log.Info(nil, "Quota service initialized successfully")
		} else {
			log.Info(nil, "Quota service is not configured")
		}
	})
}

func MergeUserQuota(reservedUserID, deletedUserID, userToken string) error {
	if quotaConfig == nil {
		log.Info(nil, "Quota service is not configured, skipping quota merge")
		return nil
	}

	if quotaConfig.BaseURL == "" {
		log.Warn(nil, "Quota service base URL is not configured, skipping quota merge")
		return nil
	}

	url := quotaConfig.BaseURL + constants.QuotaMergeURI

	request := QuotaMergeRequest{
		MainUserID:  reservedUserID,
		OtherUserID: deletedUserID,
	}

	jsonData, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal quota merge request: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create quota merge request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if userToken != "" {
		req.Header.Set("Authorization", "Bearer "+userToken)
	}

	resp, err := quotaConfig.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to call quota merge API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("quota merge API returned status: %s", resp.Status)
	}

	var response QuotaMergeResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return fmt.Errorf("failed to decode quota merge response: %w", err)
	}

	if response.Status != "success" {
		return fmt.Errorf("quota merge failed: %s", response.Message)
	}

	log.Info(nil, "Successfully merged quota from other user %s to main user %s", deletedUserID, reservedUserID)
	return nil
}
