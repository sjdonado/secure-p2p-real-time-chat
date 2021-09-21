#!/usr/bin/env python3

import socket
from Crypto.Hash import HMAC, SHA256
from threading import *
import secrets
from FP import FP
from ECPoint import ECPoint
from Parameters import Parameters
import random
from Crypto.Cipher import AES


serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = ''
port = 8002
print (host)
print (port)
serversocket.bind((host, port))

BD={'Ricardo':'Ricardo'}


class client(Thread):
    def __init__(self, socket, address,identifier, parameters):
        Thread.__init__(self)
        self.sock = socket
        self.addr = address
        self.identifier=identifier
        self.parameters=parameters
        self.start()

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


    def retrieve(self, ID):
        if ID in BD.keys():
            return BD[ID]
        else:
            raise ValueError('Error con id')

    def run(self):

        try:
            response=self.receive()

            L=self.decodeArray(response)

            ubytes=L[0]
            id_p=L[1]
            id_ps=id_p.decode('utf-8')

            pwst=self.retrieve(id_ps)



            pw=bytes(pwst,'utf-8')

            K=self.parameters.get_k(pw)

            beta=random.randint(1,self.parameters.q-1)

            V1=self.parameters.G.point_multiplication(beta)
            V2=self.parameters.B.point_multiplication(K)

            V=V1+V2

            vbytes=V.to_bytes()
            id_q=bytes(self.identifier,'utf-8')

            L=[vbytes,id_q]

            array=self.encodeArray(L)

            self.send(self.encodeArray([array]) )


            U2=self.parameters.A.point_multiplication(K)

            U=ECPoint.point_from_bytes(self.parameters.a,self.parameters.b,ubytes)

            W=(U-U2).point_multiplication(beta)

            wbytes=W.to_bytes()

            keyblob=self.parameters.H(pw,id_p,id_q, ubytes, vbytes, wbytes, 45)

            key =keyblob[:32]
            nonce = keyblob[32:]
            mask=int('0xffffffffffffffffffffffffff', base=16)
            vnonce=int.from_bytes(nonce, "big")
            cont=True

            while cont:
                data=self.receive()
                try:
                    nonce=vnonce.to_bytes(13, byteorder='big')
                    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                    plaintext = cipher.decrypt_and_verify(data[16:],data[:16])
                    vnonce=(vnonce+1)& mask
                    print(plaintext.decode('utf-8'))
                    if plaintext=='exit':
                        cont=False
                except:
                    raise RuntimeError("Encryption Error")
            self.sock.close()

        except:
            self.sock.close()


    def send(self, msg):
        totalsent = 0
        msglen=len(msg)
        while totalsent < msglen:
            sent = self.sock.send(msg[totalsent:])
            if sent == 0:
                raise RuntimeError("socket connection broken")
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



serversocket.listen(40)

print ('server started and listening')
identifier='Server'

xa=57405313773341172191899518295435281771963996349930666421087959387814856388890
ya=33669655811290356313238322911438248836339042889984235604869019563809171734975

xb=35850454933918755761577077720947914337416491049626168726415941093274263625166
yb=33735994584834933006143291579370680891499715161641162631920184782496067194454

param=Parameters(xa,ya,xb,yb)
nbytes=16
while 1:
    clientsocket, address = serversocket.accept()
    client(socket=clientsocket, address=address,identifier=identifier,parameters=param)