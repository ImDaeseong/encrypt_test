package md5util

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

type MD5 struct{}

func (m *MD5) GetMD5Text(text string) string {
	md5hash := md5.New()
	md5hash.Write([]byte(text))
	return hex.EncodeToString(md5hash.Sum(nil))
}

func (m *MD5) GetMD5File(filepath string) (string, error) {
	md5hash := md5.New()
	file, err := os.Open(filepath)
	if err != nil {
		return "", fmt.Errorf("파일 읽기 오류:%w", err)
	}
	defer file.Close()

	_, err = io.Copy(md5hash, file)
	if err != nil {
		return "", fmt.Errorf("파일 해시 오류:%w", err)
	}

	return hex.EncodeToString(md5hash.Sum(nil)), nil
}
