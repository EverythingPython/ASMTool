def decrypt_traffic(content):
    key = content[:8] + b"1Q2a3k79"
    key = hashlib.md5(key).digest()
    base64_encoded = content[8:]
    encrypted_content = base64.b64decode(base64_encoded)
    IV = 16 * b'\x00'
    mode = AES.MODE_CBC
    decryptor = AES.new(key, mode, IV)
    dec_content = decryptor.decrypt(encrypted_content)
    
    print(dec_content)