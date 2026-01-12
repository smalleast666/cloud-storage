def xor_decrypt(data, key):
    decrypted = bytearray()
    for i in range(len(data)):
        decrypted.append(data[i] ^ key[i % len(key)])
    return bytes(decrypted)

# ======== 文件路径 ========
encrypted_file = "storage/admin/test.txt"
key_file = "key_admin.bin"
output_file = "decrypted_test.txt"

# ======== 读取密钥 ========
with open(key_file, "rb") as kf:
    key = kf.read()

# ======== 读取密文 ========
with open(encrypted_file, "rb") as ef:
    encrypted_data = ef.read()

# ======== 解密 ========
decrypted_data = xor_decrypt(encrypted_data, key)

# ======== 保存明文 ========
with open(output_file, "wb") as of:
    of.write(decrypted_data)

print("✅ 解密完成，明文已保存为 decrypted_test.txt")
