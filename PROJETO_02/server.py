import socket
import threading
import json
from argon2 import PasswordHasher, exceptions as argon2_exceptions
import base64
from crypto import Crypto

database = {
    "users": [
        {
            # Password is "123"
            'username': 'user',
            'password': '$argon2id$v=19$m=65536,t=3,p=4$A5t3cz+HjiTjdy87p7+ASg$uOEVli8zhv2LBo5YohIDq412kL+jCkIONGOsTR4kNs4',
            'session_token': '',
            'crypto_key': ''
        },
        {
            # Password is "123"
            'username': 'user2',
            'password': '$argon2id$v=19$m=65536,t=3,p=4$A5t3cz+HjiTjdy87p7+ASg$uOEVli8zhv2LBo5YohIDq412kL+jCkIONGOsTR4kNs4',
            'session_token': '',
            'crypto_key': ''
        }
    ]
}


class Server:
    host = '127.0.0.1'
    tcp_port = 8080
    udp_port = 8081
    udp_clients = []

    def start(self):
        tcp_thread = threading.Thread(target=self.start_tcp_server)
        udp_thread = threading.Thread(target=self.start_udp_server)

        tcp_thread.daemon = True
        udp_thread.daemon = True

        tcp_thread.start()
        udp_thread.start()

        try:
            while True:
                pass
        except KeyboardInterrupt:
            print('Server stopped')
        finally:
            self.tcp_socket.close()
            self.udp_socket.close()
            print('Sockets closed')

    def start_tcp_server(self):
        self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_socket.bind((self.host, self.tcp_port))
        self.tcp_socket.listen()
        print(f'TCP Server listening on {self.host}:{self.tcp_port}')

        while True:
            client_socket, client_address = self.tcp_socket.accept()
            thread = threading.Thread(
                target=self.handle_tcp_client, args=(client_socket, client_address))
            thread.daemon = True
            thread.start()

    def start_udp_server(self):
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.bind((self.host, self.udp_port))
        print(f'UDP Server listening on {self.host}:{self.udp_port}')

        while True:
            data, client_address = self.udp_socket.recvfrom(1024)
            self.handle_udp_packet(data, client_address)

    def handle_tcp_client(self, client_socket: socket.socket, addr):
        data_buffer = b''
        while True:
            chunk = client_socket.recv(1024)

            if not chunk:
                break

            data_buffer += chunk

            # Check if the HTTP request is complete (ends with \r\n\r\n)
            if b"\r\n\r\n" in data_buffer:
                break

        decoded_request = data_buffer.decode('utf-8')

        print(f"Received TCP from {addr}:\n{decoded_request}")

        try:
            header, body = decoded_request.split('\r\n\r\n', 1)
            method, path, _ = header.split(' ', 2)
        except:
            print('Invalid request')
            return

        # Route the request
        if path == '/':
            if method == 'GET':
                response = self.index()
        elif path == '/login':
            if method == 'POST':
                response = self.login(body)
        elif path == '/register':
            if method == 'POST':
                response = self.register(body)
        elif path == '/logout':
            if method == 'POST':
                response = self.logout(body)
        elif path == '/online-users':
            if method == 'GET':
                response = self.online_users()
        else:
            response = self.wrap_response(404, 'text/plain', 'Not found')

        client_socket.sendall(response.encode())
        client_socket.close()

    def handle_udp_packet(self, data: bytes, addr):
        decoded_data = data.decode().strip()
        print(f'Received UDP from {addr}: {decoded_data}')

        try:
            # Remove extra double quotes if present
            if decoded_data.startswith('"') and decoded_data.endswith('"'):
                decoded_data = decoded_data[1:-1].replace('\"', '"')

            request = json.loads(decoded_data)
            if not isinstance(request, dict):
                raise ValueError("Invalid JSON received.")
        except (json.JSONDecodeError, ValueError) as e:
            print(f"JSON processing error: {e}")
            return

        # Validate token
        valid, user = self.valid_token(request.get("token"))
        if not valid:
            print("Invalid token")
            return

        # Handle file transfer
        if request.get("file_transfer"):
            self.process_file_transfer(request, user)
        else:
            self.process_message(request, user)

    def process_file_transfer(self, request: dict, user):
        filename = request.get("filename")
        file_data: str = request.get("file_data")
        target_user = request.get("to")
        chunk_index = request.get("chunk_index")
        total_chunks = request.get("total_chunks")

        if filename and file_data:
            try:
                file_data = base64.b64decode(file_data.encode('utf-8'))
                with open(f"received_server_{filename}", "wb") as file:
                    file.write(file_data)

                # Forward to recipient
                target = next(
                    (client for client in self.udp_clients if client["user"]["username"] == target_user), None)
                if target:
                    json_msg = json.dumps({
                        "from": user["username"],
                        "file_transfer": True,
                        "filename": filename,
                        "file_data": base64.b64encode(file_data).decode('utf-8'),
                        "chunk_index": chunk_index,
                        "total_chunks": total_chunks
                    })

                    self.udp_socket.sendto(
                        json_msg.encode(), target["address"])
                    print(f"File {filename} forwarded to {target_user}")
                else:
                    print(f"User {target_user} not found.")
            except Exception as e:
                print(f"Error processing file: {e}")

    def process_message(self, request: dict, user):
        message = request.get("message")
        iv = request.get("iv")
        target_user = request.get("to")

        bytes_key = bytes.fromhex(user["crypto_key"])
        decoded_message = Crypto(bytes_key).decrypt(iv, message)

        if target_user == "all":
            # Mensagem Global: Enviar para todos os clientes
            for client in self.udp_clients:
                json_msg = json.dumps(
                    {"from": user["username"], "message": decoded_message}
                )
                self.udp_socket.sendto(json_msg.encode(), client["address"])
            print(f"Mensagem global enviada por {user['username']}")
        else:
            # Mensagem Privada
            target = next(
                (client for client in self.udp_clients if client["user"]["username"] == target_user), None)
            if target:
                json_msg = json.dumps(
                    {"from": user["username"], "message": decoded_message}
                )
                self.udp_socket.sendto(json_msg.encode(), target["address"])
                print(f"Mensagem enviada para {target_user}")
            else:
                print(f"Usuário {target_user} não encontrado.")

    def wrap_response(self, status_code: int, content_type: str, body: str):
        return f"HTTP/1.1 {status_code} OK\r\nContent-Type: {content_type}\r\n\r\n{body}"

    def index(self):
        return self.wrap_response(200, 'text/plain', 'Hello, World!')

    def login(self, body: str):
        try:
            # Decodificar o corpo da requisição JSON
            data: dict = json.loads(body)
        except json.JSONDecodeError:
            return self.wrap_response(400, 'text/plain', 'Invalid JSON')

        # Extrair dados necessários
        username = data.get("username")
        password = data.get("password")
        client_udp_port = data.get("udp_port")
        client_host = data.get("host")
        client_crypto_key = data.get("crypto_key")

        # Verificar se todos os campos obrigatórios estão presentes
        if not username or not password or not client_udp_port or not client_host or not client_crypto_key:
            return self.wrap_response(400, 'text/plain', 'Missing fields in request')

        # Verificar se o usuário existe no banco de dados
        user = next(
            (u for u in database["users"] if u["username"] == username), None)
        if not user:
            return self.wrap_response(400, 'text/plain', 'User not found')

        # Verificar a senha usando Argon2
        ph = PasswordHasher()
        try:
            ph.verify(user["password"], password)
        except argon2_exceptions.VerifyMismatchError:
            return self.wrap_response(400, 'text/plain', 'Invalid password')

        # Verificar limite de conexões UDP (3 clientes no máximo)
        if len(self.udp_clients) >= 3:
            return self.wrap_response(400, 'text/plain', 'Maximum number of clients reached')

        # Gerar novo token de sessão e configurar chave de criptografia
        new_token = Crypto.generate_random_string(32)
        user["session_token"] = new_token
        user["crypto_key"] = client_crypto_key

        # Adicionar cliente à lista de clientes UDP ativos
        self.udp_clients.append({
            "address": (client_host, client_udp_port),
            "user": user
        })

        print(f"Cliente conectado: {username}")
        print(f"Clientes UDP ativos: {self.udp_clients}")

        # Retornar o token de sessão
        return self.wrap_response(200, 'text/plain', new_token)

    def register(self, body: str):
        data: dict = json.loads(body)

        username: str = data.get("username")
        password: str = data.get("password")

        if username is None or password is None:
            return self.wrap_response(400, 'text/plain', 'Missing username or password')

        if any(user["username"] == username for user in database["users"]):
            return self.wrap_response(400, 'text/plain', 'User already exists')

        ph = PasswordHasher()
        hash = ph.hash(password)

        new_user = {
            "username": username,
            "password": hash,
            "session_token": Crypto.generate_random_string(32),
            "crypto_key": None
        }

        database["users"].append(new_user)

        return self.wrap_response(200, 'text/plain', new_user["session_token"])

    def logout(self, body: str):
        data: dict = json.loads(body)

        token: str = data.get("token")

        if token is None:
            return self.wrap_response(400, 'text/plain', 'Missing session token')

        user = next((user for user in database["users"] if user.get(
            "session_token") == token), None)

        if user is None:
            return self.wrap_response(400, 'text/plain', 'Invalid session token')

        # Remover o token de sessão do usuário
        user["session_token"] = None

        # Remover o cliente da lista UDP
        self.udp_clients = [
            client for client in self.udp_clients if client["user"] != user]

        return self.wrap_response(200, 'text/plain', 'Logout successful')

    def online_users(self):
        online_users = [client["user"]["username"]
                        for client in self.udp_clients]
        return self.wrap_response(200, 'application/json', json.dumps(online_users))

    def valid_token(self, token):
        user = next(
            (user for user in database["users"] if user["session_token"] == token), None)

        if user is None:
            return False

        return True, user

    def __del__(self):
        self.tcp_socket.close()
        self.udp_socket.close()
        print('Sockets closed')


if __name__ == "__main__":
    server = Server()
    server.start()
