import socket
import json
import threading
from tkinter import Tk, Text, Entry, Button, Label, Listbox, END, filedialog, SINGLE
import os
import base64
import collections
from crypto import Crypto


class Client:
    def __init__(self):
        self.server_host = '127.0.0.1'
        self.server_tcp_port = 8080
        self.server_udp_port = 8081
        self.client_host = '127.0.0.1'
        self.session_token = None
        self.username = None
        self.crypto_client = Crypto()

        # Tkinter Configuração
        self.root = Tk()
        self.root.title("Chat Cliente")
        self.file_fragments = collections.defaultdict(
            list)  # Para armazenar fragmentos recebidos

        # Tela de Login
        self.login_frame = None
        self.username_entry = None
        self.password_entry = None

        # Tela Principal do Chat
        self.chat_frame = None
        self.recipient_listbox = None
        self.recipient = None
        self.chat_log = None
        self.message_entry = None

        self.create_login_frame()

    def create_login_frame(self):
        """Cria a tela de login."""
        self.login_frame = Label(self.root)
        self.login_frame.pack()

        Label(self.login_frame, text="Username:").grid(
            row=0, column=0, sticky="w")
        self.username_entry = Entry(self.login_frame, width=30)
        self.username_entry.grid(row=0, column=1)

        Label(self.login_frame, text="Password:").grid(
            row=1, column=0, sticky="w")
        self.password_entry = Entry(self.login_frame, width=30, show="*")
        self.password_entry.grid(row=1, column=1)

        Button(self.login_frame, text="Login", command=self.login).grid(
            row=2, column=0, columnspan=2)
        Button(self.login_frame, text="Registrar-se",
               command=self.register).grid(row=3, column=0, columnspan=2)

        self.chat_log = Text(
            self.login_frame, state='disabled', height=3, width=40)
        self.chat_log.grid(row=4, column=0, columnspan=2)

    def create_chat_frame(self):
        """Cria a tela principal do chat."""
        self.login_frame.destroy()

        self.chat_frame = Label(self.root)
        self.chat_frame.pack()

        Label(self.chat_frame, text="Usuários Online:").grid(
            row=0, column=0, sticky="w")
        self.recipient_listbox = Listbox(
            self.chat_frame, selectmode=SINGLE, height=10, width=20)
        self.recipient_listbox.grid(row=1, column=0, rowspan=2, sticky="ns")
        self.recipient_listbox.bind("<<ListboxSelect>>", self.select_recipient)

        self.chat_log = Text(
            self.chat_frame, state='disabled', height=20, width=50)
        self.chat_log.grid(row=1, column=1, columnspan=2)

        Label(self.chat_frame, text="Mensagem:").grid(
            row=2, column=1, sticky="w")
        self.message_entry = Entry(self.chat_frame, width=40)
        self.message_entry.grid(row=2, column=2)

        Button(self.chat_frame, text="Enviar Mensagem",
               command=self.send_message).grid(row=3, column=1, columnspan=2)
        Button(self.chat_frame, text="Enviar Arquivo",
               command=self.send_file).grid(row=4, column=1, columnspan=2)
        Button(self.chat_frame, text="Logout",
               command=self.logout).grid(row=5, column=1, columnspan=2)

        # Atualizar lista de usuários online
        self.update_online_users()

    def select_recipient(self, event):
        """Seleciona o destinatário ao clicar no nome."""
        selected_index = self.recipient_listbox.curselection()
        if selected_index:
            self.recipient = self.recipient_listbox.get(selected_index[0])

    def connect_tcp(self):
        self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_socket.connect((self.server_host, self.server_tcp_port))

    def update_online_users(self):
        """Solicita a lista de usuários online ao servidor."""
        self.connect_tcp()

        headers = (
            f"GET /online-users HTTP/1.1\r\n"
            f"Host: {self.server_host}\r\n"
            f"Connection: close\r\n\r\n"
        )
        self.tcp_socket.sendall(headers.encode('utf-8'))

        response = self.receive_response()

        users: dict = json.loads(response["body"])

        self.recipient_listbox.delete(0, END)
        for user in users:
            self.recipient_listbox.insert(END, user)

        # Atualizar novamente após 5 segundos
        self.root.after(5000, self.update_online_users)

    def login(self):
        """Realiza o login."""
        self.connect_tcp()
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        crypto_key = self.crypto_client.get_key()

        if not username or not password:
            self.show_error_message("Preencha todos os campos.")
            return

        payload = json.dumps({
            "username": username,
            "password": password,
            "udp_port": self.client_udp_port,
            "host": self.client_host,
            "crypto_key": crypto_key
        })

        headers = (
            f"POST /login HTTP/1.1\r\n"
            f"Host: {self.server_host}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(payload)}\r\n"
            f"Connection: close\r\n\r\n"
        )

        self.tcp_socket.sendall((headers + payload).encode('utf-8'))

        response = self.receive_response()

        if response["status"] == 200:
            self.session_token = response["body"]
            self.username = username
            self.create_chat_frame()
            threading.Thread(target=self.udp_listener, daemon=True).start()
            self.root.title(f"Chat Cliente - {self.username}")
        else:
            self.show_error_message(
                f"Erro ao realizar login: {response['body']}")

        self.tcp_socket.close()

    def register(self):
        """Registra um novo usuário."""
        self.connect_tcp()
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if not username or not password:
            self.show_error_message("Preencha todos os campos.")
            return

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

        self.tcp_socket.sendall((headers + payload).encode('utf-8'))

        response = self.receive_response()

        if response["status"] == 200:
            self.show_error_message("Usuário registrado com sucesso.")
        else:
            self.show_error_message(f"Erro ao registrar: {response['body']}")

        self.tcp_socket.close()

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

        self.chat_frame.destroy()
        self.create_login_frame()

    def send_message(self):
        if not self.recipient:
            self.add_message("Erro: Selecione um destinatário.")
            return

        message = self.message_entry.get().strip()

        encrypted_message = self.crypto_client.encrypt(message)

        if message:
            payload = {
                "token": self.session_token,
                "to": self.recipient,
                "message": encrypted_message["ciphertext"],
                "iv": encrypted_message["iv"]
            }
            self.udp_socket.sendto(json.dumps(payload).encode(
            ), (self.server_host, self.server_udp_port))
            self.add_message(f"Você para {self.recipient}: {message}")
        else:
            self.add_message("Erro: Mensagem vazia.")
        self.message_entry.delete(0, END)

    def send_file(self):
        if not self.recipient:
            self.add_message("Erro: Selecione um destinatário.")
            return

        file_path = filedialog.askopenfilename()
        if file_path:
            try:
                chunk_size = 16384  # 16 KB por pacote
                with open(file_path, "rb") as file:
                    file_data = file.read()

                filename = os.path.basename(file_path)
                total_chunks = (len(file_data) + chunk_size - 1) // chunk_size

                for chunk_index in range(total_chunks):
                    start = chunk_index * chunk_size
                    end = start + chunk_size
                    file_chunk = file_data[start:end]

                    payload = {
                        "token": self.session_token,
                        "to": self.recipient,
                        "file_transfer": True,
                        "filename": filename,
                        "chunk_index": chunk_index,
                        "total_chunks": total_chunks,
                        "file_data": base64.b64encode(file_chunk).decode()
                    }

                    self.udp_socket.sendto(json.dumps(payload).encode(
                    ), (self.server_host, self.server_udp_port))

                    self.add_message(
                        f"Pedaço {chunk_index + 1}/{total_chunks} enviado para {filename}")

                self.add_message(f"Arquivo {filename} enviado com sucesso.")
            except Exception as e:
                self.add_message(f"Erro ao enviar arquivo: {e}")

    def udp_listener(self):
        """Escuta mensagens e arquivos recebidos via UDP."""
        while True:
            try:
                data, _ = self.udp_socket.recvfrom(65535)
                received_msg: dict = json.loads(data.decode('utf-8'))

                if received_msg.get("file_transfer"):
                    filename = received_msg["filename"]
                    chunk_index = received_msg["chunk_index"]
                    total_chunks = received_msg["total_chunks"]
                    file_data: str = received_msg["file_data"]
                    file_chunk = base64.b64decode(file_data.encode())

                    self.file_fragments[filename].append(
                        (chunk_index, file_chunk))

                    if len(self.file_fragments[filename]) == total_chunks:
                        self.file_fragments[filename].sort(key=lambda x: x[0])

                        complete_file = b''.join(
                            chunk[1] for chunk in self.file_fragments[filename])

                        with open(f"received_client_{filename}", "wb") as file:
                            file.write(complete_file)

                        self.add_message(
                            f"Arquivo {filename} recebido com sucesso.")

                        del self.file_fragments[filename]
                else:
                    sender = received_msg.get("from")
                    message = received_msg.get("message")
                    self.add_message(f"{sender}: {message}")
            except Exception as e:
                self.add_message(f"Erro ao processar mensagem: {e}")

    def receive_response(self):
        response = b""
        while True:
            data = self.tcp_socket.recv(1024)
            if not data:
                break
            response += data

        if not response:
            return {"status": 500, "body": "Sem resposta do servidor."}

        try:
            decoded_response = response.decode()
            parts = decoded_response.split('\r\n\r\n', 1)
            status_line = parts[0].split(' ')
            status = int(status_line[1])
            body = parts[1]
            return {"status": status, "body": body}
        except Exception as e:
            return {"status": 500, "body": f"Erro ao processar resposta: {e}"}

    def add_message(self, message):
        """Adiciona uma mensagem ao log de chat."""
        self.chat_log.configure(state='normal')
        self.chat_log.insert(END, message + "\n")
        self.chat_log.configure(state='disabled')

    def show_error_message(self, message):
        """Exibe uma mensagem de erro no log."""
        self.add_message(message)

    def start(self):
        """Inicia o cliente."""
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.bind((self.client_host, 0))
        self.client_udp_port = self.udp_socket.getsockname()[1]

        self.root.mainloop()

    def __del__(self):
        self.logout()
        self.udp_socket.close()


if __name__ == "__main__":
    client = Client()
    client.start()
