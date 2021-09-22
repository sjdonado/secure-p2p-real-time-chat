import json

from lib.config import SERVER_CONFIG_PATH

AES_NONCE_MASK = int('0xffffffffffffffffffffffffff', base=16)

def get_server_config_by_client(id_client):
    with open(SERVER_CONFIG_PATH) as server_config_f:
        server_config_data = json.load(server_config_f)

        for server_config in server_config_data:
            if server_config['id_client'] == id_client:
                return server_config

        raise ValueError('ID Client not found')