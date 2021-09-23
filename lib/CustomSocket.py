import json

from Crypto.Cipher import AES

from lib.config import SERVER_CONFIG_PATH

AES_NONCE_MASK = int('0xffffffffffffffffffffffffff', base=16)
MAX_128_INT = int('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF', base=16)

class CustomSocket:
    def connect(self, host, port):
        self.sock.connect((host, port))

    def close(self):
        self.sock.close()

    def get_server_config_by_client(self, id_client):
        with open(SERVER_CONFIG_PATH) as server_config_f:
            server_config_data = json.load(server_config_f)

            for server_config in server_config_data:
                if server_config['id_client'] == id_client:
                    return server_config

            raise ValueError(f"ID Client: {id_client} not found")

    def encodeArray(self, arrays):
        L=[]
        for array in arrays:
            lt=len(array)
            L.append(lt.to_bytes(4,byteorder='big') +array)

        return b''.join(L)

    def decodeArray(self, barr):
        L=[]
        i=0
        while i<len(barr):
            n=int.from_bytes(barr[i:i+4], byteorder='big')
            L.append(barr[i+4:i+4+n])
            i=i+4+n
        return L

    def send(self, msg):
        totalsent = 0
        msglen=len(msg)
        while totalsent < msglen:
            sent = self.sock.send(msg[totalsent:])
            if sent == 0:
                self.sock.close()
            totalsent = totalsent + sent

    def receive(self):
        bytes_recd = 0
        chunk = self.sock.recv(4)
        if chunk == b'':
            self.sock.close()

        bytes_recd = 0
        msglen=int.from_bytes(chunk, byteorder='big')
        chunks = []
        while bytes_recd < msglen:
            chunk = self.sock.recv(min(msglen - bytes_recd, 2048))

            if chunk == b'':
                self.sock.close()
            chunks.append(chunk)
            bytes_recd = bytes_recd + len(chunk)

        return b''.join(chunks)

    def send_array(self, L):
        arr = self.encodeArray(L)
        self.send(self.encodeArray([arr]))

    def receive_array(self):
        data = self.receive()
        return self.decodeArray(data)

    def send_message(self, message, to_bytes=True):
        if to_bytes:
            message = bytes(message, 'utf-8')
        self.send(self.encodeArray([message]))

    def receive_message(self):
        message = self.receive()
        return message.decode('utf-8')

    def store_secure_credentials(self, k, id_client, id_server):
        print('k:', k.hex())
        keyblob = self.parameters.get_unique_H(4, [k], n=44)
        key = keyblob[:32]
        nonce = int.from_bytes(keyblob[32:], 'big')

        self.id_client = id_client
        self.id_server = id_server
        self.AES_key = key
        self.AES_nonce = nonce

    def encrypt_and_send(self, message):
        message = bytes(message, 'utf-8')

        noncebytes = self.AES_nonce.to_bytes(13, byteorder='big')
        cipher = AES.new(self.AES_key, AES.MODE_GCM, nonce=noncebytes)
        ciphertext, tag = cipher.encrypt_and_digest(message)
        message = tag + ciphertext
        self.send_message(message, to_bytes=False)

        self.AES_nonce = (self.AES_nonce+1)& AES_NONCE_MASK

    def receive_and_decrypt(self, array=False):
        message = self.receive()
        tag = message[16:]
        ciphertext = message[:16]

        noncebytes = self.AES_nonce.to_bytes(13, byteorder='big')
        cipher = AES.new(self.AES_key, AES.MODE_GCM, nonce=noncebytes)
        plaintext = cipher.decrypt_and_verify(tag, ciphertext)
        message = plaintext.decode('utf-8')

        self.AES_nonce = (self.AES_nonce+1)& AES_NONCE_MASK

        return message