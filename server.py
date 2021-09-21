#!/usr/bin/env python3

import socket
import random
from threading import *

from Crypto.Cipher import AES

from lib.ECPoint import ECPoint
from lib.Parameters import Parameters
from lib.CustomSocket import CustomSocket
from lib.config import HOST, PORT, XA, XB, YA, YB

BD = {'Ricardo':'Ricardo'}

class Server(Thread, CustomSocket):
    def __init__(self, socket, address,identifier, parameters):
        Thread.__init__(self)
        self.sock = socket
        self.addr = address
        self.identifier=identifier
        self.parameters=parameters
        self.start()

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

            while True:
                data=self.receive()
                try:
                    nonce=vnonce.to_bytes(13, byteorder='big')
                    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                    plaintext = cipher.decrypt_and_verify(data[16:],data[:16])
                    vnonce=(vnonce+1)& mask
                    print(plaintext.decode('utf-8'))
                    if plaintext=='exit':
                        break
                except:
                    raise RuntimeError("Encryption Error")
            self.sock.close()
        except:
            self.sock.close()


if __name__ == '__main__':
    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.bind((HOST, PORT))
    serversocket.listen()

    print (f"Server started and listening in {HOST}:{PORT}")

    identifier='Server'
    nbytes=16

    param = Parameters(XA, YA, XB, YB)

    while True:
        clientsocket, address = serversocket.accept()
        Server(socket=clientsocket, address=address,identifier=identifier,parameters=param)