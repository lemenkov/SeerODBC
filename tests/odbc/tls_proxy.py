#!/usr/bin/env python3

# SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
#
# SPDX-License-Identifier: Apache-2.0

import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading


def make_cert(dir_):
    cert = os.path.join(dir_, "proxy_cert.pem")
    key = os.path.join(dir_, "proxy_key.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", key, "-out", cert, "-days", "3650",
         "-subj", "/CN=localhost",
         "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return cert, key


def pump(src, dst):
    try:
        while True:
            buf = src.recv(8192)
            if not buf:
                break
            dst.sendall(buf)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass


def handle(ctx, client, backend_addr):
    try:
        tls = ctx.wrap_socket(client, server_side=True)
    except (ssl.SSLError, OSError):
        client.close()
        return
    try:
        back = socket.create_connection(backend_addr)
    except OSError:
        tls.close()
        return
    t1 = threading.Thread(target=pump, args=(tls, back), daemon=True)
    t2 = threading.Thread(target=pump, args=(back, tls), daemon=True)
    t1.start(); t2.start()
    t1.join(); t2.join()


def main():
    backend = (sys.argv[1], int(sys.argv[2]))
    listen_port = int(sys.argv[3]) if len(sys.argv) > 3 else 0

    tmp = tempfile.mkdtemp(prefix="seer_tlsproxy_")
    cert, key = make_cert(tmp)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", listen_port))
    srv.listen(8)
    print(f"PORT={srv.getsockname()[1]}", flush=True)
    print(f"CA={cert}", flush=True)

    while True:
        try:
            client, _ = srv.accept()
        except OSError:
            break
        threading.Thread(target=handle, args=(ctx, client, backend),
                         daemon=True).start()


if __name__ == "__main__":
    main()
