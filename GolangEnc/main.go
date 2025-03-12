// main.go
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"src/Daeseonglib/aesutil"
	"src/Daeseonglib/md5util"
	"src/Daeseonglib/sha256util"
)

func f1() {

	md5 := md5util.MD5{}
	str := md5.GetMD5Text("문자열md5")
	fmt.Println("MD5:", str, " - ", len(str))

	folderpath := `E:\Battle.net`
	files, err := os.ReadDir(folderpath)
	if err != nil {
		return
	}

	for _, file := range files {
		if !file.IsDir() {
			filePath := filepath.Join(folderpath, file.Name())
			fileHash, err := md5.GetMD5File(filePath)
			if err != nil {
				continue
			}
			fmt.Printf("md5: %s - %s - %d\n", filePath, fileHash, len(fileHash))
		}
	}
}

func f2() {
	sha256 := sha256util.SHA256{}
	str := sha256.GetSHA256Text("문자열sha256")
	fmt.Println("문자열sha256:", str, " - ", len(str))

	folderpath := `E:\Battle.net`
	files, err := os.ReadDir(folderpath)
	if err != nil {
		return
	}

	for _, file := range files {
		if !file.IsDir() {
			filePath := filepath.Join(folderpath, file.Name())
			fileHash, err := sha256.GetSHA256File(filePath, 8192)
			if err != nil {
				continue
			}
			fmt.Printf("sha256: %s - %s - %d\n", filePath, fileHash, len(fileHash))
		}
	}
}

func f3() {
	key := "12345678901234567890123456789012"
	text := "문자열AES"

	aes, err := aesutil.NewAES(key)
	if err != nil {
		fmt.Println("키 오류:", err)
		return
	}

	encrypted, err := aes.Encrypt(text)
	if err != nil {
		fmt.Println("암호화 오류:", err)
		return
	}
	fmt.Printf("AES encrypt: %s - %d\n", encrypted, len(encrypted))

	decrypted, err := aes.Decrypt(encrypted)
	if err != nil {
		fmt.Println("복호화 오류:", err)
		return
	}
	fmt.Printf("AES decrypt: %s - %d\n", decrypted, len(decrypted))
}

func main() {
	f1()
	f2()
	f3()
}
