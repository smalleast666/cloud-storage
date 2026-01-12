import socket
import hashlib
import os
import secrets

def xor_encrypt_decrypt(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9000
INIT_KEY = b'init_secret_key'
BASE_DIR = "storage"
os.makedirs(BASE_DIR, exist_ok=True)

def load_users():
    users = {}
    with open("users.txt", "r") as f:
        for line in f:
            if line.strip() and ":" in line:
                parts = line.strip().split(":")
                if len(parts) == 3:
                    username, password_hash, group = parts
                    users[username] = {"hash": password_hash, "group": group}
    return users

users = load_users()
print("当前用户数据库：", users)

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((SERVER_HOST, SERVER_PORT))
server_socket.listen(5)
print("🔐 安全网盘服务器启动，等待登录...")

while True:
    client_socket, addr = server_socket.accept()
    print(f"📥 客户端连接：{addr}")

    try:
        encrypted_login = client_socket.recv(1024)
        login_data = xor_encrypt_decrypt(encrypted_login, INIT_KEY).decode()
        username, password_hash = login_data.split("|")
        username = username.strip()
        password_hash = password_hash.strip()

        if username not in users or users[username]["hash"] != password_hash:
            client_socket.send("LOGIN_FAILED".encode())
            client_socket.close()
            continue

        client_socket.send("LOGIN_SUCCESS".encode())
        print(f"✅ 用户 {username} 登录成功")

        session_key = client_socket.recv(1024)
        print(f"🔑 会话密钥已接收：{session_key.hex()}")

        group_name = users[username]["group"]
        group_dir = os.path.join(BASE_DIR, group_name)
        os.makedirs(group_dir, exist_ok=True)

        group_key_file = f"key_{username}.bin"
        if os.path.exists(group_key_file):
            with open(group_key_file, "rb") as f:
                group_key = f.read()
        else:
            group_key = secrets.token_bytes(16)
            with open(group_key_file, "wb") as f:
                f.write(group_key)
            print(f"🔑 新组密钥已生成：{group_key.hex()}")

        # 循环处理命令
        while True:
            command = client_socket.recv(1024).decode()
            if not command or command == "EXIT":
                print(f"📴 用户 {username} 退出连接")
                break

            if command.startswith("UPLOAD"):
                _, filename, filesize = command.split("|")
                filesize = int(filesize)
                file_path = os.path.join(group_dir, filename)

                file_data = bytearray()
                while len(file_data) < filesize:
                    chunk = client_socket.recv(1024)
                    if not chunk:
                        break
                    file_data.extend(chunk)

                decrypted_once = xor_encrypt_decrypt(file_data, session_key)
                decrypted_file = xor_encrypt_decrypt(decrypted_once, group_key)

                with open(file_path, "wb") as f:
                    f.write(decrypted_file)

                # 文件hash校验
                received_hash = client_socket.recv(1024).decode()
                server_hash = hashlib.sha256(decrypted_file).hexdigest()
                if received_hash == server_hash:
                    print(f"✅ 文件完整性校验通过：{filename}")
                else:
                    print(f"❌ 文件完整性校验失败：{filename}")

                client_socket.send("UPLOAD_SUCCESS".encode())
                print(f"📁 用户 {username} 上传文件成功：{filename}")

            elif command.startswith("DOWNLOAD"):
                _, filename = command.split("|")
                file_path = os.path.join(group_dir, filename)

                if not os.path.exists(file_path):
                    client_socket.send("FILE_NOT_FOUND".encode())
                    print(f"❌ 文件 {filename} 不存在")
                    continue

                with open(file_path, "rb") as f:
                    file_bytes = f.read()

                encrypted_once = xor_encrypt_decrypt(file_bytes, group_key)
                encrypted_data = xor_encrypt_decrypt(encrypted_once, session_key)

                # 发送长度
                client_socket.send(str(len(encrypted_data)).encode())
                ack = client_socket.recv(1024)  # 等客户端确认
                client_socket.sendall(encrypted_data)

                # 发送hash
                file_hash = hashlib.sha256(file_bytes).hexdigest()
                client_socket.send(file_hash.encode())

                print(f"📥 文件 {filename} 已发送给用户 {username}")

    except Exception as e:
        print("❌ 服务器错误：", e)
    finally:
        client_socket.close()
