#!/usr/bin/env python3

import time
import socket
import random
from threading import *

from Crypto.Cipher import AES
from Crypto.Hash import SHAKE256, HMAC, SHA256

from lib.ECPoint import ECPoint
from lib.Parameters import Parameters
from lib.CustomSocket import CustomSocket, MAX_128_INT
from lib.config import SERVER_HOSTNAME, SERVER_PORT, XA, XB, YA, YB

from pre_register import generate_server_config

IP_DATABASE = {}

class Server(Thread, CustomSocket):
    def __init__(self, socket, address, parameters):
        Thread.__init__(self)
        self.sock = socket
        self.addr = address
        self.parameters = parameters
        self.start()

    def open_secure_channel(self):
        L = self.receive_array()
        ubytes = L[0]
        id_client = L[1].decode('utf-8')

        U = ECPoint.point_from_bytes(self.parameters.a, self.parameters.b, ubytes)
        self.parameters.validate_point(U)

        server_config = self.get_server_config_by_client(id_client)

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

        t_2a = self.parameters.get_unique_H(2, [k])
        t_2b = self.parameters.get_unique_H(3, [k])

        self.send_array([t_2a])
        L = self.receive_array()

        if L[0] != t_2b:
            raise ValueError('Error on validate T_1b')

        self.store_secure_credentials(k, id_client, id_server)

        print(f"**Successfully conneted to {id_client}**")

    def connect_clients(self, r_a, r_b, id_client_a, id_client_b):
        client_data_a = IP_DATABASE.get(id_client_a)
        client_data_b = IP_DATABASE.get(id_client_b)
        if client_data_a is None or client_data_b is None:
            raise ValueError(f"{id_client_a} or {id_client_b} not found")

        k_enc_b = bytes.fromhex(client_data_b[1])
        k_mac_b = bytes.fromhex(client_data_b[2])

        k = random.randint(1, MAX_128_INT**2).to_bytes(32, 'big')
        print('k ->', k.hex())

        h_256 = SHAKE256.new()
        h_256.update(k_enc_b)
        nonce = h_256.read(12)

        cipher = AES.new(k_enc_b, mode=AES.MODE_CCM, nonce=nonce)
        c_b = cipher.encrypt(k).hex()

        m = bytes(id_client_a + r_a + r_b + c_b, 'utf-8')
        h = HMAC.new(k_mac_b, digestmod=SHA256)
        h.update(m)
        t_b = h.hexdigest()

        self.encrypt_and_send(f"{c_b},{t_b}")

    def execute_command(self, message):
        if '=' in message:
            command, args = message.split('=')
            args_arr = args.split(',')
        else:
            command = None

        if command == 'ip_signup':
            ip = args_arr[0]

            k = bytes(f"{self.id_client}{time.time()}", 'utf-8')
            h_256 = SHAKE256.new()
            h_256.update(k)
            k = h_256.read(32)

            cipher = AES.new(self.AES_key, mode=AES.MODE_CCM)
            k_enc, k_mac = cipher.encrypt_and_digest(k)
            k_enc = k_enc.hex()
            k_mac = k_mac.hex()

            IP_DATABASE[self.id_client] = [ip, k_enc, k_mac, True]

            self.encrypt_and_send(f"{ip},{k_enc},{k_mac}")

        elif command == 'get_ip':
            id_ip_client = args_arr[0]

            if IP_DATABASE.get(self.id_client) is None:
                self.encrypt_and_send( f"{self.id_client} not registered")
            else:
                ip_data = IP_DATABASE.get(id_ip_client)
                if ip_data is None:
                    self.encrypt_and_send('IP Not found')
                else:
                    self.encrypt_and_send(ip_data[0])

        elif command == 'update_ip':
            ip = args_arr[0]

            if IP_DATABASE.get(self.id_client) is None:
                self.encrypt_and_send(f"{self.id_client} not registered")
            else:
                IP_DATABASE[self.id_client][0] = ip
                self.encrypt_and_send(f"{self.id_client} -> {ip} updated!")

        elif command == 'update_pass':
            client_password = args_arr[0]
            generate_server_config(self.id_client, self.id_server, client_password)
            self.encrypt_and_send(f"Password saved!")

        elif command == 'connect_clients':
            self.connect_clients(args_arr[0], args_arr[1], args_arr[2], args_arr[3])
        else:
            self.encrypt_and_send('Command not found')

    def run(self):
        try:
            self.open_secure_channel()

            while True:
                message = self.receive_and_decrypt()
                print(f"Message received from {self.id_client}:", message)

                if message == 'exit':
                    break

                self.execute_command(message)

                if 'update_pass' in message:
                    break
        except Exception as e:
            print(e)

        self.sock.close()

if __name__ == '__main__':
    parameters = Parameters(XA, YA, XB, YB)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_HOSTNAME, SERVER_PORT))
    server_socket.listen()
    print (f"Server started and listening in {SERVER_HOSTNAME}:{SERVER_PORT}")

    while True:
        client_socket, address = server_socket.accept()
        Server(client_socket, address, parameters)