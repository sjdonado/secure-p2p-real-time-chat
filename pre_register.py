#!/usr/bin/env python3

import os
import json
import argparse

from backports.pbkdf2 import pbkdf2_hmac

from lib.Parameters import Parameters
from lib.config import XA, XB, YA, YB, SERVER_CONFIG_PATH

def init_cli():
    parser = argparse.ArgumentParser(description='Generate server_config file')

    parser.add_argument('id_client', metavar='id_client', type=str,
                        help='ID_client (e.g. username)')

    parser.add_argument('id_server', metavar='id_server', type=str,
                        help='ID_server (e.g. root_server)')

    parser.add_argument('client_password', metavar='client_password', type=str,
                        help='Client password')

    parser.add_argument('--count', metavar='count', type=int, default=50000,
                        help='PBKDF2 number of rounds')

    return parser.parse_args()

def generate_server_config(id_client, id_server, client_password, count=50000):
    n = 256
    pi_size = int(n/8)
    num_bytes = 2*pi_size
    salt = os.urandom(16)
    payload = bytes(client_password+id_client+id_server, 'utf-8')

    h = pbkdf2_hmac('sha512', payload, salt, count, num_bytes)

    param = Parameters(XA, YA, XB, YB)

    pi_0 = int.from_bytes(h[:pi_size], 'big') % param.q
    pi_1 = int.from_bytes(h[pi_size:], 'big') % param.q
    c = param.G.point_multiplication(pi_1).to_bytes().hex()

    if os.path.exists(SERVER_CONFIG_PATH):
        with open(SERVER_CONFIG_PATH) as server_config_f:
            server_config_data = json.load(server_config_f)

        for elem in server_config_data:
            if elem['id_client'] == id_client:
               server_config_data.remove(elem)
               break
    else:
        server_config_data = []

    server_config_data.append({
        'id_client': id_client,
        'id_server': id_server,
        'pi_0': pi_0,
        'pi_1': pi_1,
        'c': c
    })

    with open(SERVER_CONFIG_PATH, 'w') as json_file:
        json.dump(server_config_data, json_file, indent=4)

    print(f"{SERVER_CONFIG_PATH} created/updated!")

if __name__ == '__main__':
    args = init_cli()
    id_client = args.id_client
    id_server = args.id_server
    client_password = args.client_password
    count = args.count

    generate_server_config(id_client, id_server, client_password, count)
