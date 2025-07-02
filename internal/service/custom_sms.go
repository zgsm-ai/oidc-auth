package service

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/zgsm-ai/oidc-auth/internal/config"
	"github.com/zgsm-ai/oidc-auth/internal/constants"
	"github.com/zgsm-ai/oidc-auth/pkg/log"
)

var (
	smsCfg *config.SMSConfig
	once   sync.Once
)

type SMSRequest struct {
	SystemCode string `json:"systemCode"`
	Phone      string `json:"phone"`
	Content    string `json:"content"`
}

type SMSResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Rows string `json:"rows"` // SMS ID
}

func GetSMSCfg(cfg *config.SMSConfig) *config.SMSConfig {
	once.Do(func() {
		if cfg == nil {
			log.Error(nil, "SMS configuration is nil")
			return
		}
		smsCfg = cfg
		log.Info(nil, "SMS configuration initialized successfully")
	})
	return smsCfg
}

func pkcs5Padding(src []byte) []byte {
	padding := constants.BlockSize - len(src)%constants.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func AesEncrypt(plainText, key string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	iv := []byte(constants.IV)[:constants.BlockSize]

	paddedData := pkcs5Padding([]byte(plainText))
	ciphertext := make([]byte, len(paddedData))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedData)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func GetLoginCode(clientID, clientSecret string) (string, error) {
	timestamp := fmt.Sprintf("%d", time.Now().UnixNano()/1e6)
	content := fmt.Sprintf(`{"clientId":"%s","timesstamp":"%s"}`, clientID, timestamp)
	return AesEncrypt(content, clientSecret)
}

type JWTTokenResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Rows struct {
		AccessToken string `json:"access_token"`
	} `json:"rows"`
}

func GetJWTToken(loginCode, clientID string, httpClient *http.Client) (string, error) {
	baseURL := GetSMSCfg(nil).TokenURL

	params := url.Values{}
	params.Add("loginCode", loginCode)
	params.Add("clientId", clientID)

	fullURL := fmt.Sprintf("%s?%s", baseURL, params.Encode())

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	req, err := http.NewRequest("POST", fullURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "OIDC-Auth-Client/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP error: %d, response: %s", resp.StatusCode, string(body))
	}

	var jwtResp JWTTokenResponse
	if err := json.Unmarshal(body, &jwtResp); err != nil {
		return "", fmt.Errorf("failed to parse JSON: %v, response: %s", err, string(body))
	}

	if jwtResp.Code != 0 {
		return "", fmt.Errorf("failed to get token: %s (code: %d)", jwtResp.Msg, jwtResp.Code)
	}

	accessToken := jwtResp.Rows.AccessToken
	if accessToken == "" {
		return "", fmt.Errorf("access_token is empty in response")
	}

	if strings.HasPrefix(accessToken, "Bearer ") {
		return strings.TrimPrefix(accessToken, "Bearer "), nil
	}

	return accessToken, nil
}

func SendSMS(client *http.Client, token, phone, content string) (*SMSResponse, error) {
	sendURL := GetSMSCfg(nil).SendURL

	if strings.HasPrefix(phone, "+86") {
		phone = strings.TrimPrefix(phone, "+86")
	}
	smsReq := SMSRequest{
		SystemCode: "shenma",
		Phone:      phone,
		Content:    content,
	}

	jsonData, err := json.Marshal(smsReq)
	if err != nil {
		return nil, fmt.Errorf("JSON encoding failed: %v", err)
	}

	req, err := http.NewRequest("POST", sendURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("create request failed: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "OIDC-Auth-Client/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response failed: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error: %d, %s", resp.StatusCode, string(body))
	}

	var smsResp SMSResponse
	if err := json.Unmarshal(body, &smsResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v, response: %s", err, string(body))
	}

	if smsResp.Code != 0 {
		return nil, fmt.Errorf("SMS API error: %s (code: %d)", smsResp.Msg, smsResp.Code)
	}

	return &smsResp, nil
}
