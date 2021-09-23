import os

from dotenv import load_dotenv
load_dotenv()

SERVER_HOSTNAME = os.environ.get('SERVER_HOSTNAME', '127.0.0.1')
SERVER_PORT = int(os.environ.get('SERVER_PORT', 8000))
XA = int(os.environ.get('XA', 57405313773341172191899518295435281771963996349930666421087959387814856388890))
XB = int(os.environ.get('XB', 35850454933918755761577077720947914337416491049626168726415941093274263625166))
YA = int(os.environ.get('YA', 33669655811290356313238322911438248836339042889984235604869019563809171734975))
YB = int(os.environ.get('YB', 33735994584834933006143291579370680891499715161641162631920184782496067194454))
SERVER_CONFIG_PATH = 'server_config.json'