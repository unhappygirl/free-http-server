

import socket
import time
import threading
import random


def enormous_load():
    for i in range(1000):
        s = socket.socket()
        s.connect(("localhost", 31331))
        s.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        print(f"I am socket {i}, I received {s.recv(1024)}")
        s.close()


def one_load(s):
    s.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
    s.recv(1024)
    time.sleep(0.001)


def random_loads():
    t = random.randint(1, 20)
    s = socket.socket()
    s.connect(("localhost", 31331))
    while t != 0:
        if random.randint(0, 4) == 1:
            one_load(s)
        t -= 1
        time.sleep(0.2)


def persistent_load():
    threads = []
    for i in range(3000):
        thread = threading.Thread(target=random_loads)
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()


if __name__ == "__main__":
    # enormous_load()
    persistent_load()
