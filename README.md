Secure P2P messaging chat
===

1. Pre register protocol
2. Client-Server secure communication
3. Client-Client secure communication

## Setup

- Create virtual env
```bash
python3 -m venv env
```

- Install dependencies
```bash
pip install -r requirements.txt
```

- Pre register
```bash
./pre_register.py user_a root_server userapass
./pre_register.py user_b root_server userbpass
```

## How to run?

To display help run: `./client.py --help`
To run in verbose mode: `./client.py --verbose`

- Open the server in a new terminal
```bash
./server.py
```

- Open the client **B** in a new terminal
```bash
./client.py user_b 127.0.0.1:8001 --point-a user_a
```

- Open the client **A** in a new terminal
```bash
./client.py user_a 127.0.0.1:8002 --point-b user_b
```

- To exit write `exit` in all client terminals

## Server interactive session

Run allowed commands: `ip_signup`, `get_ip`, `update_ip`, `update_pass`, `exit`
NOTE: make sure to be registered before or run `ip_signup`

```bash
./client.py user_a 127.0.0.1:8001 --server-interactive-session
```