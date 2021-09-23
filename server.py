#!/usr/bin/env python3

import time
import socket
import random
import argparse
from threading import *

from Crypto.Cipher import AES
from Crypto.Hash import SHAKE256, HMAC, SHA256

from lib.ECPoint import ECPoint
from lib.Parameters import Parameters
from lib.CustomSocket import CustomSocket, MAX_128_INT
from lib.config import SERVER_HOSTNAME, SERVER_PORT, XA, XB, YA, YB

from pre_register import generate_server_config

IP_DATABASE = {}

def init_cli():
    parser = argparse.ArgumentParser(description='The sever stores the IP data of all clients')

    parser.add_argument('-v', '--verbose', dest="verbose", default=False,
                    action='store_true', help='Display chiphertext and keys')

    return parser.parse_args()


class Server(Thread, CustomSocket):
    def __init__(self, socket, address, parameters, verbose=False):
        Thread.__init__(self)
        self.sock = socket
        self.addr = address
        self.parameters = parameters
        self.verbose = verbose
        self.start()

    def client_server_key_exchange(self):
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

        id_server = id_server.decode('utf-8')

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

    def ip_signup(self, args_arr):
        ip = args_arr[0]

        k = bytes(f"{self.id_client}{time.time()}", 'utf-8')
        h_256 = SHAKE256.new()
        h_256.update(k)
        k = h_256.read(32)

        cipher = AES.new(self.AES_key, mode=AES.MODE_CCM)
        k_enc, k_mac = cipher.encrypt_and_digest(k)
        k_enc = k_enc.hex()
        k_mac = k_mac.hex()

        IP_DATABASE[self.id_client] = {
            'ip': ip,
            'k_enc': k_enc,
            'k_mac': k_mac,
            'registered': True
        }

        self.encrypt_and_send(f"{ip},{k_enc},{k_mac}")

    def get_ip(self, args_arr):
        id_ip_client = args_arr[0]
        if IP_DATABASE.get(self.id_client) is None:
            self.encrypt_and_send( f"{self.id_client} not registered")
        else:
            ip_data = IP_DATABASE.get(id_ip_client)
            if ip_data is None:
                self.encrypt_and_send('IP Not found')
            else:
                self.encrypt_and_send(ip_data['ip'])

    def update_ip(self, args_arr):
        ip = args_arr[0]
        if IP_DATABASE.get(self.id_client) is None:
            self.encrypt_and_send(f"{self.id_client} not registered")
        else:
            IP_DATABASE[self.id_client]['ip'] = ip
            self.encrypt_and_send('IP updated!')

    def update_pass(self, args_arr):
        client_password = args_arr[0]
        print(self.id_client)
        print(self.id_server)
        print(client_password)
        generate_server_config(self.id_client, self.id_server, client_password)
        self.encrypt_and_send('Password saved!, reopen connection to continue')

    def get_c_and_t(self, k_enc, k_mac, id_client, k, r_a, r_b):
        h_256 = SHAKE256.new()
        h_256.update(k_enc)
        nonce = h_256.read(12)

        cipher = AES.new(k_enc, mode=AES.MODE_CCM, nonce=nonce)
        c = cipher.encrypt(k).hex()

        m = bytes(id_client + r_a + r_b + c, 'utf-8')
        h = HMAC.new(k_mac, digestmod=SHA256)
        h.update(m)
        t = h.hexdigest()

        return (c, t)

    def clients_key_exchange(self, args_arr):
        [r_a, r_b, id_client_a, id_client_b] = args_arr

        client_data_a = IP_DATABASE.get(id_client_a)
        client_data_b = IP_DATABASE.get(id_client_b)
        if client_data_a is None or client_data_b is None:
            raise ValueError(f"{id_client_a} or {id_client_b} not found")

        k = random.randint(1, MAX_128_INT**2).to_bytes(32, 'big')

        k_enc_b = bytes.fromhex(client_data_b['k_enc'])
        k_mac_b = bytes.fromhex(client_data_b['k_mac'])

        c_b, t_b = self.get_c_and_t(k_enc_b, k_mac_b, id_client_a, k, r_a, r_b)
        IP_DATABASE[id_client_b]['c_b'] = c_b
        IP_DATABASE[id_client_b]['t_b'] = t_b
        self.encrypt_and_send(f"{c_b},{t_b}")

        k_enc_a = bytes.fromhex(client_data_a['k_enc'])
        k_mac_a = bytes.fromhex(client_data_a['k_mac'])

        c_a, t_a = self.get_c_and_t(k_enc_a, k_mac_a, id_client_b, k, r_a, r_b)
        IP_DATABASE[id_client_a]['c_a'] = c_a
        IP_DATABASE[id_client_a]['t_a'] = t_a
        IP_DATABASE[id_client_a]['id_client_b'] = id_client_b
        IP_DATABASE[id_client_a]['r_b'] = r_b

    def get_keys(self, args_arr):
        client_data = IP_DATABASE.get(self.id_client)
        if client_data is None:
            self.encrypt_and_send( f"{self.id_client} not registered")
        message = f"{client_data['id_client_b']},{client_data['r_b']}"
        message += f",{client_data['c_a']},{client_data['t_a']}"
        self.encrypt_and_send(message)

    def default_command(self, args_arr):
        self.encrypt_and_send('Command not found')

    def execute_command(self, message):
        if '=' in message:
            command, args = message.split('=')
            args_arr = args.split(',')
        else:
            command = message
            args_arr = None

        COMMANDS = {
            'ip_signup': self.ip_signup,
            'get_ip': self.get_ip,
            'update_ip': self.update_ip,
            'update_pass': self.update_pass,
            'clients_key_exchange': self.clients_key_exchange,
            'get_keys': self.get_keys,
        }
        COMMANDS.get(command, self.default_command)(args_arr)

    def run(self):
        try:
            self.client_server_key_exchange()
            while True:
                message = self.receive_and_decrypt()
                print(f"Message received from {self.id_client}:", message)

                if message == 'exit':
                    break

                self.execute_command(message)
        except Exception as e:
            print(e)

        self.sock.close()

if __name__ == '__main__':
    args = init_cli()
    verbose = args.verbose
    parameters = Parameters(XA, YA, XB, YB)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_HOSTNAME, SERVER_PORT))
    server_socket.listen()
    print (f"Server listening at {SERVER_HOSTNAME}:{SERVER_PORT}")

    while True:
        client_socket, address = server_socket.accept()
        Server(client_socket, address, parameters, verbose=verbose)