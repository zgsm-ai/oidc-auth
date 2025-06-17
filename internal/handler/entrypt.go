package handler

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"time"
)

const (
	IV        = "TRYTOCN314402233" // 固定16字节IV
	BlockSize = aes.BlockSize      // AES-128 块大小固定16字节
)

// PKCS5Padding 填充
func pkcs5Padding(src []byte) []byte {
	padding := BlockSize - len(src)%BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

// PKCS5Unpadding 去除填充
func pkcs5Unpadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

// AesEncrypt AES/CBC/PKCS5Padding 加密
func AesEncrypt(plainText, key string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	// 确保IV是16字节
	iv := []byte(IV)[:BlockSize]

	// 填充明文
	paddedData := pkcs5Padding([]byte(plainText))

	// 加密
	ciphertext := make([]byte, len(paddedData))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedData)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// AesDecrypt AES/CBC/PKCS5Padding 解密
func AesDecrypt(cipherText, key string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	// 解码Base64
	decoded, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	// 检查数据长度
	if len(decoded)%BlockSize != 0 {
		return "", fmt.Errorf("invalid ciphertext length: %d (must be multiple of %d)", len(decoded), BlockSize)
	}

	// 确保IV是16字节
	iv := []byte(IV)[:BlockSize]

	// 解密
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(decoded))
	mode.CryptBlocks(plaintext, decoded)

	// 去除填充
	plaintext = pkcs5Unpadding(plaintext)

	return string(plaintext), nil
}

// GetLoginCode 生成登录加密数据
func GetLoginCode(clientID, clientSecret string) (string, error) {
	timestamp := fmt.Sprintf("%d", time.Now().UnixNano()/1e6)
	content := fmt.Sprintf(`{"clientId":"%s","timesstamp":"%s"}`, clientID, timestamp)
	return AesEncrypt(content, clientSecret)
}

func generateCode(clinetid string) {
	key := "a80982a50d0b4f7a98db6b91fdaf34ae"
	loginCode, err := GetLoginCode("1724993521440", key)
	if err != nil {
		panic(err)
	}
	fmt.Println("Login Code:", loginCode)
}
