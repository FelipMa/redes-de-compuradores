import socket
import threading
import json
from argon2 import PasswordHasher, exceptions as argon2_exceptions
import random
import string

database = {
    "users": [
        {
            # Password is "123"
            'email': 'user1@test.com',
            'password': '$argon2id$v=19$m=65536,t=3,p=4$A5t3cz+HjiTjdy87p7+ASg$uOEVli8zhv2LBo5YohIDq412kL+jCkIONGOsTR4kNs4',
            'session_token': '01234567890123456789012345678901'
        },
        {
            # Password is "123"
            'email': 'user2@test.com',
            'password': '$argon2id$v=19$m=65536,t=3,p=4$A5t3cz+HjiTjdy87p7+ASg$uOEVli8zhv2LBo5YohIDq412kL+jCkIONGOsTR4kNs4',
            'session_token': '01234567890123456789012345678902'
        }
    ]
}


class Server:
    host = '127.0.0.1'
    tcp_port = 8080
    udp_port = 8081

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

        try:
            header, body = decoded_request.split('\r\n\r\n', 1)
            method, path, _ = header.split(' ', 2)
        except ValueError:
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
        else:
            response = self.wrap_response(404, 'text/plain', 'Not found')

        client_socket.sendall(response.encode())

        client_socket.close()

    def handle_udp_packet(self, data: bytes, addr):
        print(f'Received UDP from {addr}: {data.decode()}')

        self.udp_socket.sendto(data, addr)

    def wrap_response(self, status_code: int, content_type: str, body: str):
        return f"HTTP/1.1 {status_code} OK\r\nContent-Type: {content_type}\r\n\r\n{body}"

    def index(self):
        return self.wrap_response(200, 'text/plain', 'Hello, World!')

    def login(self, body: str):
        data: dict = json.loads(body)

        email: str = data.get("email")
        password: str = data.get("password")

        if email is None or password is None:
            return self.wrap_response(400, 'text/plain', 'Missing email or password')

        try:
            user = next(
                user for user in database["users"] if user["email"] == email)
        except StopIteration:
            return self.wrap_response(400, 'text/plain', 'User not found')

        ph = PasswordHasher()
        try:
            ph.verify(user["password"], password)
        except argon2_exceptions.VerifyMismatchError:
            return self.wrap_response(400, 'text/plain', 'Invalid password')

        new_token = self.generate_random_string(32)
        user["session_token"] = new_token

        return self.wrap_response(200, 'text/plain', user["session_token"])

    def register(self, body: str):
        data: dict = json.loads(body)

        email: str = data.get("email")
        password: str = data.get("password")

        if email is None or password is None:
            return self.wrap_response(400, 'text/plain', 'Missing email or password')

        if any(user["email"] == email for user in database["users"]):
            return self.wrap_response(400, 'text/plain', 'User already exists')

        ph = PasswordHasher()
        hash = ph.hash(password)

        new_user = {
            "email": email,
            "password": hash,
            "session_token": self.generate_random_string(32)
        }

        database["users"].append(new_user)

        return self.wrap_response(200, 'text/plain', new_user["session_token"])

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

        return True


if __name__ == "__main__":
    server = Server()
    server.start()
