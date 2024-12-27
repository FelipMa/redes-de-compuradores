import socket
import json
import threading


class Client:
    server_host = '127.0.0.1'
    server_tcp_port = 8080
    server_udp_port = 8081
    client_host = '127.0.0.1'

    def start(self):
        self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_socket.connect((self.server_host, self.server_tcp_port))

        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.bind((self.client_host, 0))
        self.client_udp_port = self.udp_socket.getsockname()[1]

        udp_listener_thread = threading.Thread(target=self.udp_listener)
        udp_listener_thread.daemon = True
        udp_listener_thread.start()

        self.login()

        while True:
            print()
            print('Digite "exit" para sair')
            print('Digite "m" para enviar uma mensagem')
            option = input()

            if option == 'exit':
                break

            if option == 'm':
                target_user = input("Digite o username do destinatário: ")
                message = input("Digite uma mensagem: ")
                self.send_message_to_user(message, target_user)

        self.tcp_socket.close()
        self.udp_socket.close()

    def login(self):
        username = input("Digite seu username: ")
        password = input("Digite sua senha: ")

        payload = json.dumps(
            {
                "username": username,
                "password": password,
                "udp_port": self.client_udp_port,
                "host": self.client_host
            })

        headers = (
            f"POST /login HTTP/1.1\r\n"
            f"Host: {self.server_host}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(payload)}\r\n"
            f"Connection: close\r\n\r\n"
        )

        request = headers + payload

        self.tcp_socket.sendall(request.encode('utf-8'))

        response = b""
        while True:
            data = self.tcp_socket.recv(1024)
            if not data:
                break
            response += data

        response_decoded = response.decode('utf-8')
        status_code = response_decoded.split(' ')[1]
        response_body = response_decoded.split('\r\n\r\n', 1)[1]

        if status_code == '200':
            self.session_token = response_body
            print('Login realizado com sucesso')
        else:
            print('Erro ao realizar login')
            print(response_body)
            self.login()

    def send_message_to_user(self, message, target_user):
        obj = json.dumps({
            'token': self.session_token,
            'to': target_user,
            'message': message
        })

        pack = json.dumps(obj)

        self.udp_socket.sendto(
            pack.encode(), (self.server_host, self.server_udp_port)
        )

    def udp_listener(self):
        print('UDP listener started')
        while True:
            data, addr = self.udp_socket.recvfrom(1024)
            print()
            print(f'Nova mensagem de {addr}')
            data_obj = json.loads(data)
            print(f'De: {data_obj["from"]}')
            print(f'Mensagem: {data_obj["message"]}')


if __name__ == "__main__":
    client = Client()
    client.start()
