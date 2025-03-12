import base64
import os
from Crypto.Cipher import AES as CryptoAES
from Crypto.Util.Padding import pad, unpad


class AES:
    def __init__(self, key):
        if len(key) != 32:
            raise ValueError("키값이 32바이트가 아닌 경우")

        self.key = key.encode('utf-8')  # 키를 바이트 형식으로 변환
        self.block_size = CryptoAES.block_size  # 블록 크기 (AES의 기본 블록 크기)

    def encrypt_text(self, text):
        iv = os.urandom(self.block_size)  # 초기화 벡터(IV) 생성
        cipher = CryptoAES.new(self.key, CryptoAES.MODE_CBC, iv)  # AES CBC 모드로 암호화 객체 생성

        plaintext = text.encode('utf-8')  # 입력 텍스트를 바이트 형식으로 변환
        padded_plaintext = pad(plaintext, self.block_size)  # 패딩을 추가하여 블록 크기에 맞춤

        ciphertext = cipher.encrypt(padded_plaintext)  # 암호화

        result = base64.b64encode(iv + ciphertext).decode('utf-8')  # IV와 암호문을 결합한 후 base64 인코딩
        return result

    def decrypt_text(self, text):
        try:
            raw = base64.b64decode(text)  # base64로 인코딩된 텍스트를 디코딩

            iv = raw[:self.block_size]  # IV 추출 (앞부분)
            ciphertext = raw[self.block_size:]  # 암호문 추출 (그 나머지 부분)

            cipher = CryptoAES.new(self.key, CryptoAES.MODE_CBC, iv)  # AES CBC 모드로 복호화 객체 생성

            padded_plaintext = cipher.decrypt(ciphertext)  # 복호화
            plaintext = unpad(padded_plaintext, self.block_size)  # 패딩 제거

            return plaintext.decode('utf-8')

        except Exception as e:
            raise ValueError(f"복호화 오류: {e}")
