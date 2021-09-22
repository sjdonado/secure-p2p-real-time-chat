#!/usr/bin/env python3

import time
import socket
import random
from threading import *

from Crypto.Cipher import AES
from Crypto.Hash import SHAKE256

from lib.ECPoint import ECPoint
from lib.Parameters import Parameters
from lib.CustomSocket import CustomSocket
from lib.config import HOST, PORT, XA, XB, YA, YB
from lib.utils import get_server_config_by_client, AES_NONCE_MASK

IP_DATABASE = {}

class Server(Thread, CustomSocket):
    def __init__(self, socket, address, parameters):
        Thread.__init__(self)
        self.sock = socket
        self.addr = address
        self.parameters = parameters
        self.start()

    def init_key_exchange(self):
        L = self.receive_array()
        ubytes = L[0]
        id_client = L[1].decode('utf-8')

        U = ECPoint.point_from_bytes(self.parameters.a, self.parameters.b, ubytes)
        self.parameters.validate_point(U)

        server_config = get_server_config_by_client(id_client)

        beta = random.randint(1,self.parameters.q-1)

        V1 = self.parameters.G.point_multiplication(beta)
        V2 = self.parameters.B.point_multiplication(server_config['pi_0'])
        V = V1 + V2

        vbytes = V.to_bytes()
        id_server = bytes(server_config['id_server'], 'utf-8')

        L = [vbytes, id_server]
        self.send_array(L)

        W1 = self.parameters.A.point_multiplication(server_config['pi_0'])
        W = (U - W1).point_multiplication(beta)

        C_hex = bytes.fromhex(server_config['c'])
        C = ECPoint.point_from_bytes(self.parameters.a, self.parameters.b, C_hex)
        d = C.point_multiplication(beta)

        wbytes = W.to_bytes()
        dbytes = d.to_bytes()
        pi_0_bytes = server_config['pi_0'].to_bytes(32, byteorder='big')

        k = self.parameters.get_unique_H(1, [pi_0_bytes, ubytes, vbytes, wbytes, dbytes])

        print('k', k.hex())

        t_2a = self.parameters.get_unique_H(2, [k])
        t_2b = self.parameters.get_unique_H(3, [k])

        self.send_array([t_2a])
        L = self.receive_array()

        if L[0] != t_2b:
            raise ValueError('Error on validate T_1b')

        keyblob = self.parameters.get_unique_H(4, [k], n=44)
        key = keyblob[:32]
        nonce = keyblob[32:]

        print(f"**Successfully conneted to {id_client}**")

        return ((key, nonce), id_client)

    def execute_command(self, AES_keys, id_client, message):
        if ':' in message:
            command, args = message.split(':')
            args_arr = args.split(',')
        else:
            command = None

        if command == 'ip_signup':
            ip = args_arr[0]

            k = bytes(f"{id_client}|{time.time()}", 'utf-8')
            h_256 = SHAKE256.new()
            h_256.update(k)
            k = h_256.read(32)

            cipher = AES.new(AES_keys[0], mode=AES.MODE_EAX)
            k_enc, k_mac = cipher.encrypt_and_digest(k)

            IP_DATABASE[id_client] = [ip, k_enc, k_mac, True]
            self.send_message(f"[server]: {id_client} -> {ip} registered!")

        elif command == 'get_ip':
            id_ip_client = args_arr[0]

            if IP_DATABASE.get(id_client) is None:
                self.send_message(f"[server]: {id_client} not registered")
            else:
                ip_data = IP_DATABASE.get(id_ip_client)
                if ip_data is None:
                    self.send_message('[server]: IP Not found')
                else:
                    self.send_message(f"[server]: {ip_data[0]}")

        elif command == 'update_ip':
            ip = args_arr[0]

            if IP_DATABASE.get(id_client) is None:
                self.send_message(f"[server]: {id_client} not registered")
            else:
                IP_DATABASE[id_client][0] = ip
                self.send_message(f"[server]: {id_client} -> {ip} updated!")
        else:
            self.send_message('[server]: Command not found')

    def run(self):
        # try:
        (AES_keys, id_client) = self.init_key_exchange()

        (key, nonce) = AES_keys
        nonce = int.from_bytes(nonce, 'big')

        while True:
            data = self.receive()

            noncebytes = nonce.to_bytes(13, byteorder='big')
            cipher = AES.new(key, AES.MODE_GCM, nonce=noncebytes)
            tag = data[16:]
            ciphertext = data[:16]
            plaintext = cipher.decrypt_and_verify(tag, ciphertext)
            message = plaintext.decode('utf-8')
            print(f"Message received from {id_client}:", message)

            if message == 'exit':
                break

            self.execute_command(AES_keys, id_client, message)
            nonce = (nonce+1)& AES_NONCE_MASK
        # except Exception as e:
        #     print(e)

        self.sock.close()

if __name__ == '__main__':
    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.bind((HOST, PORT))
    serversocket.listen()
    print (f"Server started and listening in {HOST}:{PORT}")

    param = Parameters(XA, YA, XB, YB)

    while True:
        clientsocket, address = serversocket.accept()
        Server(socket=clientsocket, address=address, parameters=param)