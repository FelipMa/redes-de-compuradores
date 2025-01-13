import socket
import json
import threading
import os
import base64


class Client:
    server_host = '127.0.0.1'
    server_tcp_port = 8080
    server_udp_port = 8081
    client_host = '127.0.0.1'

    def start(self):
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.bind((self.client_host, 0))
        self.client_udp_port = self.udp_socket.getsockname()[1]

        udp_listener_thread = threading.Thread(target=self.udp_listener)
        udp_listener_thread.daemon = True
        udp_listener_thread.start()

        while True:
            print('\nEscolha uma opção:')
            print('1 - Registrar-se')
            print('2 - Login')
            option = input("Digite sua escolha: ")

            control = True

            if option == '1':
                self.register()
                break
            elif option == '2':
                control = self.login()
                break
            else:
                print('Opção inválida')

        if option == '1' or control == False:
            self.start()

        # Loop principal
        while True:
            print()
            print('Digite "exit" para sair')
            print('Digite "m" para enviar uma mensagem')
            print('Digite "f" para enviar um arquivo')
            option = input()

            if option == 'exit':
                self.logout()
                break

            if option == 'm':
                target_user = input("Digite o username do destinatário: ")
                message = input("Digite uma mensagem: ")
                self.send_message_to_user(message, target_user)

            if option == 'f':
                target_user = input("Digite o username do destinatário: ")
                file_path = input("Digite o caminho do arquivo: ")
                self.send_file_to_user(file_path, target_user)

        self.udp_socket.close()

    def connect_tcp(self):
        self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_socket.connect((self.server_host, self.server_tcp_port))

    def register(self):
        self.connect_tcp()
        username = input("Escolha um username: ")
        password = input("Escolha uma senha: ")

        payload = json.dumps({
            "username": username,
            "password": password
        })

        headers = (
            f"POST /register HTTP/1.1\r\n"
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
            print('Registro realizado com sucesso. Token de sessão:', response_body)
        else:
            print('Erro ao realizar registro')
            print(response_body)
            self.register()

        self.tcp_socket.close()

    def login(self):
        self.connect_tcp()
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
            self.tcp_socket.close()
            return True
        else:
            print('Erro ao realizar login')
            print(response_body)
            self.tcp_socket.close()
            return False

    def logout(self):
        self.connect_tcp()
        payload = json.dumps({
            "token": self.session_token
        })

        headers = (
            f"POST /logout HTTP/1.1\r\n"
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
            print('Logout realizado com sucesso')
        else:
            print('Erro ao realizar logout')
            print(response_body)

        self.tcp_socket.close()

    def send_file_to_user(self, filename, target_user):
        try:
            with open(filename, "rb") as file:
                file_data = base64.b64encode(file.read()).decode('utf-8')

            pack = json.dumps({
                "token": self.session_token,
                "to": target_user,
                "file_transfer": True,
                "filename": filename,
                "file_data": file_data
            })

            self.udp_socket.sendto(pack.encode(
                'utf-8'), (self.server_host, self.server_udp_port))

            print(f"Arquivo {filename} enviado com sucesso para {target_user}")

        except FileNotFoundError:
            print("Arquivo não encontrado.")
        except Exception as e:
            print(f"Erro ao enviar o arquivo: {e}")

    def send_message_to_user(self, message, target_user):
        obj = json.dumps({
            'token': self.session_token,
            'to': target_user,
            'message': message
        })

        pack = json.dumps(obj)
        self.udp_socket.sendto(
            pack.encode(), (self.server_host, self.server_udp_port))

    def udp_listener(self):
        while True:
            data, addr = self.udp_socket.recvfrom(4096)
            try:
                data_obj: dict = json.loads(data.decode('utf-8'))

                # Se for um arquivo
                if data_obj.get("file_transfer"):
                    filename = data_obj.get("filename")
                    file_data: str = data_obj.get("file_data")

                    if filename and file_data:
                        file_data = base64.b64decode(file_data.encode('utf-8'))
                        filename = os.path.basename(filename)

                        # Salvar o arquivo localmente
                        with open(f"received_client_{filename}", "wb") as file:
                            file.write(file_data)
                        print(
                            f"Arquivo {filename} recebido e salvo com sucesso.")
                    else:
                        print("Erro: Dados de arquivo incompletos.")

                # Se for uma mensagem de texto
                else:
                    print(f'Nova mensagem!')
                    print(f'De: {data_obj["from"]}')
                    print(f'Mensagem: {data_obj["message"]}')

            except Exception as e:
                print(f"Erro ao processar mensagem UDP: {e}")


if __name__ == "__main__":
    client = Client()
    client.start()
