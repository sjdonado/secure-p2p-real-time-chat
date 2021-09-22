#!/usr/bin/env python3

import socket
import random
from threading import *

from Crypto.Cipher import AES

from lib.ECPoint import ECPoint
from lib.Parameters import Parameters
from lib.CustomSocket import CustomSocket
from lib.config import HOST, PORT, XA, XB, YA, YB
from lib.utils import get_server_config_by_client, AES_NONCE_MASK

class Client(CustomSocket):
    def __init__(self, sock, id_client, host, port, parameters):
        if sock is None:
            self.sock = socket.socket(
            socket.AF_INET, socket.SOCK_STREAM)
        else:
            self.sock = sock

        self.host=host
        self.port=port
        self.parameters=parameters
        self.server_config = get_server_config_by_client(id_client)

    def init_key_exchange(self):
        alpha = random.randint(1, self.parameters.q-1)

        U1 = self.parameters.G.point_multiplication(alpha)
        U2 = self.parameters.A.point_multiplication(self.server_config['pi_0'])
        U = U1 + U2

        ubytes = U.to_bytes()
        id_client = bytes(self.server_config['id_client'], 'utf-8')

        L = [ubytes, id_client]
        self.send_array(L)

        L = self.receive_array()
        vbytes = L[0]
        id_server = L[1].decode('utf-8')

        if id_server != self.server_config['id_server']:
            raise ValueError('ID server not match')

        V = ECPoint.point_from_bytes(self.parameters.a, self.parameters.b, vbytes)
        self.parameters.validate_point(V)

        V2 = self.parameters.B.point_multiplication(self.server_config['pi_0'])
        W = (V - V2).point_multiplication(alpha)

        d = (V - V2).point_multiplication(self.server_config['pi_1'])

        wbytes = W.to_bytes()
        dbytes = d.to_bytes()
        pi_0_bytes = self.server_config['pi_0'].to_bytes(32, byteorder='big')

        k = self.parameters.get_unique_H(1, [pi_0_bytes, ubytes, vbytes, wbytes, dbytes])

        print('k', k.hex())

        t_1a = self.parameters.get_unique_H(2, [k])
        t_1b = self.parameters.get_unique_H(3, [k])

        self.send_array([t_1b])
        L = self.receive_array()

        if L[0] != t_1a:
            raise ValueError('Error on validate T_2a')

        keyblob = self.parameters.get_unique_H(4, [k], n=44)
        key = keyblob[:32]
        nonce = keyblob[32:]

        print(f"**Successfully conneted to {id_server}**")

        return ((key, nonce), id_server)

    def run(self):
        self.sock.connect((self.host, self.port))
        (AES_keys, id_server) = self.init_key_exchange()

        (key, nonce) = AES_keys
        nonce = int.from_bytes(nonce, 'big')

        print('Allowed commands: ip_signup, get_ip, update_ip, update_pass, exit')
        print('Send COMMAND:ARG1,ARG2...')
        print('Example: ip_signup:192.168.1.2')
        while True:
            message = input('> ')
            message = bytes(message, 'utf-8')

            noncebytes = nonce.to_bytes(13, byteorder='big')
            cipher = AES.new(key, AES.MODE_GCM, nonce=noncebytes)
            ciphertext, tag = cipher.encrypt_and_digest(message)
            message = tag + ciphertext
            # print('Ciphertext:', data.hex())
            self.send_message(message, to_bytes=False)
            nonce = (nonce+1)& AES_NONCE_MASK

            if message == 'exit':
                break

            response = self.receive()
            print(response.decode('utf-8'))

        self.sock.close()

if __name__ == '__main__':
    param = Parameters(XA, YA, XB, YB)
    client = Client(None, 'sjdonado' , HOST, PORT, param)
    client.run()
