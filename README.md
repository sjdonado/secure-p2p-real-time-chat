Secure P2P messaging chat
===

## 1. Pre register protocol

Generate and store `pi_0`, `pi_1` and `c`
![image](https://user-images.githubusercontent.com/27580836/134527220-a926b40b-2340-4a62-bcac-de9a9070cb0a.png)

## 2. Client-Server secure connection

### Key exchange

![image](https://user-images.githubusercontent.com/27580836/134527601-9d273d1d-0cc2-4042-afc4-8d3667c42781.png)
![image](https://user-images.githubusercontent.com/27580836/134527698-6047a83e-1e50-464b-a73b-3dbd37e5e9a4.png)

### Communication

![image](https://user-images.githubusercontent.com/27580836/134527977-34c6b30f-f6a8-4f6c-ad00-603c7e5aa84b.png)


## 3. Client-Client secure connection

### Key exchange
![image](https://user-images.githubusercontent.com/27580836/134528081-57bbd54b-2eb8-4850-83f8-c3800d312806.png)

### Communication

Same as **2**: AES GCM using `k_ab`, `k_ba` and `N`

# Setup

### 1. Create virtual env
```bash
python3 -m venv env
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Pre register
```bash
./pre_register.py user_a root_server userapass
./pre_register.py user_b root_server userbpass
```

# How to run?

- To display help: `./client.py --help`
- To run in verbose mode: `./client.py --verbose`
- To exit write `exit` in all terminals

## Step by step

### 1. Open the server in a new terminal
```bash
./server.py
```

### 2. Open the client **B** in a new terminal
```bash
./client.py user_b 127.0.0.1:8001 --point-a user_a
```

### 3. Open the client **A** in a new terminal
```bash
./client.py user_a 127.0.0.1:8002 --point-b user_b
```

## Server interactive session

Run allowed commands: `ip_signup`, `get_ip`, `update_ip`, `update_pass`, `exit`
NOTE: make sure to be registered before or run `ip_signup`

```bash
./client.py user_a 127.0.0.1:8001 --server-interactive-session
```

# Demo
![Screen Recording 2021-09-23 at 9 52 25 AM](https://user-images.githubusercontent.com/27580836/134535042-2bcbca52-5846-48a1-9861-0aec7028be29.gif)

