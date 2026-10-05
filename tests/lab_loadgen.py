import json
import os
import socket
import sys
import threading
import time

mode = sys.argv[1]
vip, port = sys.argv[2], int(sys.argv[3])


def read_node(sock):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(512)
        if not chunk:
            return ""
        data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    length, node = 0, ""
    for line in head.decode("latin-1").splitlines():
        name, _, value = line.partition(":")
        if name.lower() == "content-length":
            length = int(value.strip())
        elif name.lower() == "x-node":
            node = value.strip()
    while len(body) < length:
        chunk = sock.recv(512)
        if not chunk:
            break
        body += chunk
    return node


def fetch(path="/", timeout=0.4):
    sock = socket.socket()
    sock.settimeout(timeout)
    try:
        sock.connect((vip, port))
        sock.sendall(f"GET {path} HTTP/1.1\r\nHost: lab.example.com\r\nConnection: close\r\n\r\n".encode())
        node = read_node(sock)
        return ("ok", node) if node else ("fail", "")
    except OSError:
        return ("fail", "")
    finally:
        sock.close()


if mode == "load":
    rate, seconds, out = float(sys.argv[4]), float(sys.argv[5]), sys.argv[6]
    lock = threading.Lock()
    lines = []

    def one(started):
        status, node = fetch()
        with lock:
            lines.append(f"{started:.4f} {status} {node}")

    end = time.time() + seconds
    threads = []
    while time.time() < end:
        started = time.time()
        thread = threading.Thread(target=one, args=(started,), daemon=True)
        thread.start()
        threads.append(thread)
        time.sleep(max(0.0, 1.0 / rate - (time.time() - started)))
    for thread in threads:
        thread.join(timeout=2.0)
    with open(out, "w") as handle:
        handle.write("\n".join(lines) + "\n")
elif mode == "distribution":
    count = int(sys.argv[4])
    seen = {}
    for _ in range(count):
        status, node = fetch()
        seen[node or status] = seen.get(node or status, 0) + 1
    print(json.dumps(seen, sort_keys=True))
elif mode == "hold":
    count, trigger, out = int(sys.argv[4]), sys.argv[5], sys.argv[6]
    request = b"GET / HTTP/1.1\r\nHost: lab.example.com\r\n\r\n"
    conns = []
    for _ in range(count):
        sock = socket.socket()
        sock.settimeout(1.0)
        try:
            sock.connect((vip, port))
            sock.sendall(request)
            node = read_node(sock)
            if node:
                conns.append((sock, node))
            else:
                sock.close()
        except OSError:
            sock.close()
    while not os.path.exists(trigger):
        time.sleep(0.05)
    result = {}
    for sock, node in conns:
        try:
            sock.sendall(request)
            now_node = read_node(sock)
            outcome = "same_node" if now_node == node else ("other_node" if now_node else "closed")
        except OSError:
            outcome = "reset_or_timeout"
        bucket = result.setdefault(node, {})
        bucket[outcome] = bucket.get(outcome, 0) + 1
    with open(out, "w") as handle:
        handle.write(json.dumps(result, sort_keys=True))
