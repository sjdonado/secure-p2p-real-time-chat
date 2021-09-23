#!/usr/bin/env python3

import sys
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

def init_cli():
    parser = argparse.ArgumentParser(description='The client can connect to other clients or to the server')

    parser.add_argument('id_client', metavar='id_client', type=str,
                        help='ID_client (e.g. sjdonado)')

    parser.add_argument('client_host', metavar='client_host', type=str,
                        help='Client host (e.g. 127.0.0.1:8001)')

    parser.add_argument('--point-a', metavar='point_a', type=str,
                        default=None, help='ID client of point A (e.g. sjdonado)')

    parser.add_argument('--point-b', metavar='point_b', type=str,
                        default=None, help='ID client of point B (e.g. tester)')

    parser.add_argument('--server-interactive-session',
                        dest="server_interactive_session", default=False,
                        action='store_true', help='Connect to server and send commands')

    return parser.parse_args()

class Client(Thread, CustomSocket):
    def __init__(self, socket, id_client, parameters, AES_key=None, AES_nonce=None):
        Thread.__init__(self)
        self.sock = socket
        self.parameters = parameters
        self.id_client = id_client
        self.server_config = self.get_server_config_by_client(id_client)
        self.AES_key = AES_key
        self.AES_nonce = AES_nonce
        self.start()

    def open_secure_channel(self):
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

        t_1a = self.parameters.get_unique_H(2, [k])
        t_1b = self.parameters.get_unique_H(3, [k])

        self.send_array([t_1b])
        L = self.receive_array()

        if L[0] != t_1a:
            raise ValueError('Error on validate T_2a')

        self.store_secure_credentials(k, id_client, id_server)

    def server_interactive_session(self):
        self.connect(SERVER_HOSTNAME, SERVER_PORT)
        self.open_secure_channel()
        print(f"**Successfully conneted to {self.id_server}**")

        print('Allowed commands: ip_signup, get_ip, update_ip, update_pass, exit')
        print('Send COMMAND=ARG1,ARG2,...')
        print('Example: ip_signup=127.0.0.1:8001')
        while True:
            message = input('> ')
            self.encrypt_and_send(message)

            if message == 'exit':
                break

            response = self.receive_and_decrypt()
            print('[server]:', response)

            if message == 'update_pass':
                self.server_config = self.get_server_config_by_client(self.id_client)
                break

        self.sock.close()

    def start_chat_send_channel(self):
        while True:
            message = input('> ')
            self.encrypt_and_send(message)

            if message == 'exit':
                break

        self.sock.close()

    def start_chat_listen_channel(self):
        while True:
            try:
                message = self.receive_and_decrypt()
                print('[received]:', message)

                if message == 'exit':
                    break
            except Exception as e:
                print(e)

        self.sock.close()

def open_client_socket(id_client, parameters, AES_key=None, AES_nonce=None):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    return Client(client_socket, id_client, parameters, AES_key, AES_nonce)

def open_server_socket(id_client, host, port, AES_key=None, AES_nonce=None):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen()

    print(f"Server initialized, wainting for connections")

    client_a_socket, address = server_socket.accept()

    return Client(client_a_socket, id_client, parameters, AES_key, AES_nonce)

def get_client_shared_keys(k_enc, k_mac, id_client_a, id_client_b, r_a, r_b, m, c, t):
    h = HMAC.new(k_mac, digestmod=SHA256)
    h.update(m)

    if h.hexdigest() != t:
        raise ValueError('MAC not valid')

    h_256 = SHAKE256.new()
    h_256.update(k_enc)
    nonce = h_256.read(12)

    cipher = AES.new(k_enc, mode=AES.MODE_CCM, nonce=nonce)
    k = cipher.decrypt(bytes.fromhex(c))

    if int.from_bytes(k, byteorder='big') > MAX_128_INT**2:
        raise ValueError('k out of range')

    data = [
        bytes(id_client_a, 'utf-8'),
        bytes(id_client_b, 'utf-8'),
        bytes(r_a, 'utf_8'),
        bytes(r_b, 'utf_8')
    ]

    keys = parameters.get_unique_H(6, data, n=76)
    k_ab = keys[:32]
    k_ba = keys[32:64]
    N = keys[64:]

    return ((k_ab, k_ba), N)

if __name__ == '__main__':
    args = init_cli()
    id_client = args.id_client
    client_host = args.client_host
    point_a = args.point_a
    point_b = args.point_b
    server_interactive_session = args.server_interactive_session

    [client_ip, client_port] = client_host.split(':')
    client_port = int(client_port)

    parameters = Parameters(XA, YA, XB, YB)

    client_server = open_client_socket(id_client, parameters)

    if server_interactive_session:
        client_server.server_interactive_session()
        sys.exit(0)

    if point_b:
        """ Client A"""
        client_server.connect(SERVER_HOSTNAME, SERVER_PORT)
        client_server.open_secure_channel()

        client_server.encrypt_and_send(f"ip_signup={client_ip}:{client_port}")
        message = client_server.receive_and_decrypt()
        [ip, k_enc_a, k_mac_a] = message.split(',')
        k_enc_a = bytes.fromhex(k_enc_a)
        k_mac_a = bytes.fromhex(k_mac_a)

        client_server.encrypt_and_send(f"get_ip={point_b}")
        message = client_server.receive_and_decrypt()

        [client_b_ip, client_b_port] = message.split(':')
        client_b_port = int(client_b_port)

        client_a = open_client_socket(id_client, parameters)
        client_a.connect(client_b_ip, client_b_port)

        r_a = str(random.randint(1, MAX_128_INT))

        client_a.send_array([bytes(r_a, 'utf-8'), bytes(id_client, 'utf-8')])

        client_b_status = client_a.receive_message()
        if client_b_status != 'status:done':
            print('Error on client_b')
            sys.exit(0)

        client_server.encrypt_and_send(f"get_keys")
        message = client_server.receive_and_decrypt()
        client_server.close()
        [id_client_b, r_b, c_a, t_a] = message.split(',')

        m = bytes(id_client_b + r_a + r_b + c_a, 'utf-8')
        (shared_keys, N) = get_client_shared_keys(k_enc_a, k_mac_a, id_client,
                                                    id_client_b, r_a, r_b, m, c_a,
                                                    t_a)
        [k_ab, k_ba] = shared_keys

        N = int.from_bytes(N, 'big')

        # server_a = open_server_socket(id_client, client_ip, client_port,
        #                               AES_key=k_ab, AES_nonce=N)
        # server_a.start_chat_listen_channel()

        client_a.AES_key = k_ba
        client_a.AES_nonce = N
        client_a.start_chat_send_channel()

    if point_a:
        """ Client B"""
        client_server.connect(SERVER_HOSTNAME, SERVER_PORT)
        client_server.open_secure_channel()

        client_server.encrypt_and_send(f"ip_signup={client_ip}:{client_port}")
        message = client_server.receive_and_decrypt()
        [ip, k_enc_b, k_mac_b] = message.split(',')
        k_enc_b = bytes.fromhex(k_enc_b)
        k_mac_b = bytes.fromhex(k_mac_b)

        server_b = open_server_socket(id_client, client_ip, client_port)
        message = server_b.receive_array()
        r_a = message[0].decode('utf-8')
        id_client_a = message[1].decode('utf-8')

        r_b = str(random.randint(1, MAX_128_INT))

        message = f"connect_clients={r_a},{r_b},{id_client_a},{id_client}"
        client_server.encrypt_and_send(message)
        message = client_server.receive_and_decrypt()
        client_server.close()

        [c_b, t_b] = message.split(',')

        m = bytes(id_client_a + r_a + r_b + c_b, 'utf-8')
        (shared_keys, N) = get_client_shared_keys(k_enc_b, k_mac_b, id_client_a,
                                                  id_client, r_a, r_b, m, c_b, t_b)
        [k_ab, k_ba] = shared_keys

        server_b.send_message('status:done')

        server_b.AES_key = k_ba
        server_b.AES_nonce = int.from_bytes(N, 'big')
        server_b.start_chat_listen_channel()

        # client_b = open_client_socket(id_client, parameters, AES_key=k_ab, AES_nonce=N)
        # client_b.connect()
        # client_b.start_chat_send_channel()

