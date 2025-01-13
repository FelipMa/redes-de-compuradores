import socket
import threading
import json
from argon2 import PasswordHasher, exceptions as argon2_exceptions
import random
import string
import base64

database = {
    "users": [
        {
            # Password is "123"
            'username': 'user',
            'password': '$argon2id$v=19$m=65536,t=3,p=4$A5t3cz+HjiTjdy87p7+ASg$uOEVli8zhv2LBo5YohIDq412kL+jCkIONGOsTR4kNs4',
            'session_token': '01234567890123456789012345678901'
        },
        {
            # Password is "123"
            'username': 'user2',
            'password': '$argon2id$v=19$m=65536,t=3,p=4$A5t3cz+HjiTjdy87p7+ASg$uOEVli8zhv2LBo5YohIDq412kL+jCkIONGOsTR4kNs4',
            'session_token': '01234567890123456789012345678902'
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

        print(f'Received TCP from {addr}:\n{decoded_request}')

        try:
            header, body = decoded_request.split('\r\n\r\n', 1)
            method, path, _ = header.split(' ', 2)
        except:
            print('Invalid request')

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
        elif path == '/upload':
            if method == 'POST':
                response = self.upload_file(body)
        else:
            response = self.wrap_response(404, 'text/plain', 'Not found')

        client_socket.sendall(response.encode())

        client_socket.close()

    def handle_udp_packet(self, data: bytes, addr):
        decoded_data = data.decode().strip()
        print(f'Received UDP from {addr}: {decoded_data}')

        try:
            # Remover aspas duplas extras, se presentes
            if decoded_data.startswith('"') and decoded_data.endswith('"'):
                decoded_data = decoded_data[1:-1].replace('\\"', '"')

            request = json.loads(decoded_data)
            if not isinstance(request, dict):
                raise ValueError("O dado recebido não é um JSON válido.")
        except (json.JSONDecodeError, ValueError) as e:
            print(f"Erro ao processar o JSON: {e}")
            return

        # Validação de token
        valid, user = self.valid_token(request.get("token"))
        if not valid:
            print("Invalid token")
            return

        # Transferência de Arquivo
        if request.get("file_transfer") == True:
            filename = request.get("filename")
            file_data: str = request.get("file_data")
            target_user = request.get("to")

            if filename and file_data:
                try:
                    file_data = base64.b64decode(file_data.encode('utf-8'))
                    with open(f"received_server_{filename}", "wb") as file:
                        file.write(file_data)
                    print(f"Arquivo {filename} salvo com sucesso.")

                    # Encaminhar para o destinatário
                    target = next(
                        (client for client in self.udp_clients if client["user"]["username"] == target_user), None)
                    if target:
                        json_msg = json.dumps({
                            "from": user["username"],
                            "file_transfer": True,
                            "filename": filename,
                            "file_data": base64.b64encode(file_data).decode('utf-8')
                        })
                        self.udp_socket.sendto(
                            json_msg.encode(), target["address"])
                        print(
                            f"Arquivo {filename} encaminhado para {target_user}")
                    else:
                        print(f"Usuário {target_user} não encontrado.")
                except Exception as e:
                    print(f"Erro ao processar o arquivo: {e}")

        # Mensagens de Texto
        else:
            message = request.get("message")
            target_user = request.get("to")

            target = next(
                (client for client in self.udp_clients if client["user"]["username"] == target_user), None)
            if target:
                json_msg = json.dumps(
                    {"from": user["username"], "message": message})
                self.udp_socket.sendto(json_msg.encode(), target["address"])
                print(f"Mensagem enviada para {target_user}")
            else:
                print("Usuário não encontrado.")

    def wrap_response(self, status_code: int, content_type: str, body: str):
        return f"HTTP/1.1 {status_code} OK\r\nContent-Type: {content_type}\r\n\r\n{body}"

    def index(self):
        return self.wrap_response(200, 'text/plain', 'Hello, World!')

    def login(self, body: str):
        data: dict = json.loads(body)

        username: str = data.get("username")
        password: str = data.get("password")
        client_udp_port: int = data.get("udp_port")
        client_host: str = data.get("host")

        if username is None or password is None:
            return self.wrap_response(400, 'text/plain', 'Missing username or password')

        try:
            user = next(
                user for user in database["users"] if user["username"] == username)
        except StopIteration:
            return self.wrap_response(400, 'text/plain', 'User not found')

        ph = PasswordHasher()
        try:
            ph.verify(user["password"], password)
        except argon2_exceptions.VerifyMismatchError:
            return self.wrap_response(400, 'text/plain', 'Invalid password')

        # Verifica se o número de clientes UDP já atingiu o limite de 3
        if len(self.udp_clients) >= 3:
            return self.wrap_response(400, 'text/plain', 'Maximum number of clients reached')

        new_token = self.generate_random_string(32)
        user["session_token"] = new_token

        user_without_password = user.copy()
        del user_without_password["password"]

        self.udp_clients.append({
            "address": (client_host, client_udp_port),
            "user": user
        })

        print("Clientes UDP ativos: ", self.udp_clients)

        return self.wrap_response(200, 'text/plain', user["session_token"])

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
            "session_token": self.generate_random_string(32)
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

    def generate_random_string(self, length):
        characters = string.ascii_letters + string.digits
        random_string = ''.join(random.choice(characters)
                                for i in range(length))
        return random_string

    def valid_token(self, token):
        user = next(
            (user for user in database["users"] if user["session_token"] == token), None)

        if user is None:
            return False

        return True, user

    def upload_file(self, body: str):
        try:
            # Espera que o body seja um JSON com nome de arquivo e conteúdo base64
            data: dict = json.loads(body)
            filename = data.get("filename")
            file_content = data.get("content")  # Conteúdo codificado em base64

            # Decodificando o conteúdo base64
            import base64
            file_bytes = base64.b64decode(file_content)

            # Salvando o arquivo no servidor
            with open(f"uploads/{filename}", "wb") as file:
                file.write(file_bytes)

            return self.wrap_response(200, 'text/plain', f'Arquivo {filename} recebido com sucesso.')

        except Exception as e:
            return self.wrap_response(500, 'text/plain', f'Erro ao processar o arquivo: {str(e)}')

    def receive_udp_file(self, data: dict, addr):
        filename = data.get("filename")
        file_content = data.get("content")  # Recebe conteúdo como base64
        import base64
        try:
            file_bytes = base64.b64decode(file_content)
            with open(f"uploads/{filename}", "ab") as file:
                file.write(file_bytes)
            print(f"Recebido parte do arquivo {filename} de {addr}")
        except Exception as e:
            print(f"Erro ao receber arquivo UDP: {e}")


if __name__ == "__main__":
    server = Server()
    server.start()
