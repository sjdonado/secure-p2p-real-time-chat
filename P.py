#!/usr/bin/env python3

import socket
from Crypto.Hash import HMAC, SHA256
from threading import *
import random
from FP import FP
from ECPoint import ECPoint
from Parameters import Parameters
from Crypto.Cipher import AES

class P:
    def __init__(self,sock, identifier, password ,host, port, parameters):

        if sock is None:
            self.sock = socket.socket(
            socket.AF_INET, socket.SOCK_STREAM)
        else:
            self.sock = sock
        self.host=host
        self.port=port

        self.password=password
        self.identifier=identifier
        self.parameters=parameters

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


    def run(self):
        self.connect(self.host, self.port)

        alpha=random.randint(1,self.parameters.q-1)
        U1=self.parameters.G.point_multiplication(alpha)

        pw=bytes(self.password,'utf-8')
        K=self.parameters.get_k(pw)
        U2=self.parameters.A.point_multiplication(K)

        U=U1+U2

        ubytes=U.to_bytes()
        id_p=bytes(self.identifier,'utf-8')

        L=[ubytes,id_p]

        array=self.encodeArray(L)


        array=self.encodeArray([array])


        self.send(array)

        arrayRec=self.receive()

        L=self.decodeArray(arrayRec)

        vbytes=L[0]
        id_q=L[1]

        V=ECPoint.point_from_bytes(self.parameters.a,self.parameters.b,vbytes)

        V2=self.parameters.B.point_multiplication(K)

        W=(V-V2).point_multiplication(alpha)

        wbytes=W.to_bytes()

        keyblob=self.parameters.H(pw,id_p,id_q,ubytes, vbytes,wbytes, 45)

        key =keyblob[:32]
        nonce = keyblob[32:]
        mask=int('0xffffffffffffffffffffffffff', base=16)
        #print(keyblob.hex())
        vnonce=int.from_bytes(nonce, "big")
        cont=True
        while cont:
            print("Escriba un mensaje para enviar: Si escribe 'exit' finaliza")
            message=input()

            data=bytes(message,'utf-8')
            nonce=vnonce.to_bytes(13, byteorder='big')
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            print(ciphertext)
            vnonce=(vnonce+1)& mask
            array=self.encodeArray([tag+ciphertext])
            self.send(array)

            if message=='exit':
                cont=False


        self.sock.close()


    def connect(self, host, port):
        self.sock.connect((host, port))
        #c=self.receive()


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

host='192.168.0.10'
port=8002
identifier='Ricardo'
pw='Ricardo'

xa=57405313773341172191899518295435281771963996349930666421087959387814856388890
ya=33669655811290356313238322911438248836339042889984235604869019563809171734975

xb=35850454933918755761577077720947914337416491049626168726415941093274263625166
yb=33735994584834933006143291579370680891499715161641162631920184782496067194454

param=Parameters(xa,ya,xb,yb)
client=P(None,identifier, pw ,host,port, param)
client.run()
