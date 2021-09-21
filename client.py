#!/usr/bin/env python3

import socket
import random
from threading import *

from Crypto.Cipher import AES

from lib.ECPoint import ECPoint
from lib.Parameters import Parameters
from lib.CustomSocket import CustomSocket
from lib.config import HOST, PORT, XA, XB, YA, YB

class Client(CustomSocket):
    def __init__(self, sock, identifier, password , host, port, parameters):
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

    def connect(self, host, port):
        self.sock.connect((host, port))
        #c=self.receive()

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

        while True:
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
                break

        self.sock.close()

if __name__ == '__main__':
    identifier='Ricardo'
    pw='Ricardo'

    param = Parameters(XA, YA, XB, YB)
    client=Client(None, identifier, pw , HOST, PORT, param)
    client.run()
