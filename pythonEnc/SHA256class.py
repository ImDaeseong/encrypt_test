import hashlib


class SHA256:
    def getSHA256_text(self, text):
        sha256hash = hashlib.sha256()
        sha256hash.update(text.encode('utf-8'))
        return sha256hash.hexdigest()

    def getSHA256_file(self, filepath, chunk_size=8192):
        sha256hash = hashlib.sha256()
        try:
            with open(filepath, 'rb') as file:
                for chunk in iter(lambda: file.read(chunk_size), b''):
                    sha256hash.update(chunk)
            return sha256hash.hexdigest()
        except IOError as e:
            raise IOError(f"파일 읽기 오류: {e}")
