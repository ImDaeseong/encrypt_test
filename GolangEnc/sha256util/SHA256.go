package sha256util

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

type SHA256 struct{}

func (s *SHA256) GetSHA256Text(text string) string {
	hash := sha256.New()
	hash.Write([]byte(text))
	return hex.EncodeToString(hash.Sum(nil))
}

func (s *SHA256) GetSHA256File(filepath string, chunkSize int) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", fmt.Errorf("파일 읽기 오류: %v", err)
	}
	defer file.Close()

	hash := sha256.New()
	buffer := make([]byte, chunkSize)
	for {
		n, err := file.Read(buffer)
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", fmt.Errorf("파일 읽기 오류: %v", err)
		}
		hash.Write(buffer[:n])
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
