class CustomSocket:
    def encodeArray(self,arrays):
        L=[]
        for array in arrays:
            lt=len(array)
            L.append(lt.to_bytes(4,byteorder='big') +array)

        return b''.join(L)

    def decodeArray(self,barr):
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