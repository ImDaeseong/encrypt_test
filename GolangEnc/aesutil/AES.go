package aesutil

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

type AES struct {
	key []byte
}

func NewAES(key string) (*AES, error) {
	if len(key) != 32 {
		return nil, errors.New("키값이 32바이트가 아닌 경우")
	}
	return &AES{key: []byte(key)}, nil
}

func (a *AES) Encrypt(text string) (string, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return "", err
	}

	plaintext := []byte(text)
	blockSize := block.BlockSize()

	// IV 생성
	iv := make([]byte, blockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	// 패딩 적용
	plaintext = pad(plaintext, blockSize)

	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	// IV와 암호문을 결합 후 base64 인코딩
	result := append(iv, ciphertext...)
	return base64.StdEncoding.EncodeToString(result), nil
}

func (a *AES) Decrypt(text string) (string, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return "", err
	}

	decoded, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return "", err
	}

	blockSize := block.BlockSize()
	if len(decoded) < blockSize {
		return "", errors.New("복호화 오류: 데이터 길이가 올바르지 않음")
	}

	// IV와 암호문 분리
	iv := decoded[:blockSize]
	ciphertext := decoded[blockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	// 패딩 제거
	plaintext, err := unpad(ciphertext, blockSize)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// PKCS7 패딩 적용
func pad(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

// PKCS7 패딩 제거
func unpad(src []byte, blockSize int) ([]byte, error) {
	length := len(src)
	if length == 0 || length%blockSize != 0 {
		return nil, errors.New("잘못된 패딩")
	}

	padding := int(src[length-1])
	if padding > length || padding > blockSize {
		return nil, errors.New("잘못된 패딩 값")
	}

	return src[:length-padding], nil
}
