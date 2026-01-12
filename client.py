import socket
import hashlib
import os
import secrets

def xor_encrypt_decrypt(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9000
INIT_KEY = b'init_secret_key'

# 登录
username = input("用户名：")
password = input("密码：")
password_hash = hashlib.sha256(password.encode()).hexdigest()

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((SERVER_HOST, SERVER_PORT))

login_data = f"{username}|{password_hash}".encode()
encrypted_login = xor_encrypt_decrypt(login_data, INIT_KEY)
client_socket.send(encrypted_login)

response = client_socket.recv(1024).decode()
if response != "LOGIN_SUCCESS":
    print("❌ 登录失败")
    client_socket.close()
    exit()
print("✅ 登录成功")

# 会话密钥
session_key = secrets.token_bytes(16)
print(f"🔑 本次会话密钥已生成：{session_key.hex()}")
client_socket.send(session_key)

# 用户组密钥
group_key_file = f"key_{username}.bin"
if not os.path.exists(group_key_file):
    print(f"❌ 用户组密钥 {group_key_file} 不存在")
    client_socket.close()
    exit()
with open(group_key_file, "rb") as f:
    group_key = f.read()
print(f"🔑 用户组密钥已加载：{group_key.hex()}")

# 主循环
while True:
    action = input("请选择操作：1-上传 2-下载 3-退出：")
    if action == "1":
        filepath = input("请输入要上传的文件路径：")
        if not os.path.exists(filepath):
            print("❌ 文件不存在")
            continue
        filename = os.path.basename(filepath)
        filesize = os.path.getsize(filepath)
        client_socket.send(f"UPLOAD|{filename}|{filesize}".encode())

        with open(filepath, "rb") as f:
            file_data = f.read()
        file_hash = hashlib.sha256(file_data).hexdigest()
        print("📄 文件完整性摘要：", file_hash)

        encrypted_once = xor_encrypt_decrypt(file_data, group_key)
        encrypted_data = xor_encrypt_decrypt(encrypted_once, session_key)
        client_socket.sendall(encrypted_data)
        client_socket.send(file_hash.encode())

        result = client_socket.recv(1024).decode()
        if result == "UPLOAD_SUCCESS":
            print(f"📁 文件 {filename} 上传成功")
        else:
            print(f"❌ 文件 {filename} 上传失败")

    elif action == "2":
        download_name = input("请输入要下载的文件名：")
        client_socket.send(f"DOWNLOAD|{download_name}".encode())

        # 接收文件长度
        file_size = int(client_socket.recv(1024).decode())
        client_socket.send(b"OK")  # 确认收到长度

        # 接收文件内容
        received_data = bytearray()
        while len(received_data) < file_size:
            chunk = client_socket.recv(1024)
            if not chunk:
                break
            received_data.extend(chunk)

        decrypted_once = xor_encrypt_decrypt(received_data, session_key)
        decrypted_file = xor_encrypt_decrypt(decrypted_once, group_key)

        save_path = f"download_{download_name}"
        with open(save_path, "wb") as f:
            f.write(decrypted_file)

        # 校验hash
        file_hash = client_socket.recv(1024).decode()
        local_hash = hashlib.sha256(decrypted_file).hexdigest()
        if file_hash == local_hash:
            print(f"📁 文件 {download_name} 下载成功，完整性校验通过")
        else:
            print(f"❌ 文件 {download_name} 下载失败，完整性校验错误")

    elif action == "3":
        client_socket.send("EXIT".encode())
        print("📴 退出客户端")
        break
    else:
        print("❌ 无效选项，请选择 1/2/3")

client_socket.close()
