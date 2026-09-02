import socket

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 53))
    print("Port 53 is available and successfully bound!")
    s.close()
except Exception as e:
    print(f"Port 53 bind error: {e}")
