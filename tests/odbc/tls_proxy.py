#!/usr/bin/env python3

# SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
#
# SPDX-License-Identifier: Apache-2.0

# A terminating TLS proxy for the matrix's TLS check: it takes TLS on a local
# port and forwards the plaintext to a listener.
#
# usage: tls_proxy.py BACKEND_HOST BACKEND_PORT [LISTEN_PORT]
#
# A listener can answer the CONNECT with a REDIRECT to another address, as
# 8i's Windows listener does to a dedicated server port. The driver follows
# the REDIRECT's (HOST=..)(PORT=..), which would go around the proxy, so the
# proxy rewrites them to a second local TLS port forwarding to that address
# (#412). Only the handshake is read packet by packet: from the first reply
# that isn't a RESEND on, the bytes go through untouched.

import os
import re
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading

TNS_PT_REDIRECT = 5
TNS_PT_RESEND = 11
TNS_HEADER_LEN = 8
LISTEN_HOST = "127.0.0.1"


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


def close_both(a, b):
    for s in (a, b):
        try:
            s.shutdown(socket.SHUT_RDWR)
        except OSError:
            # already closed by the other direction's pump
            pass
        try:
            s.close()
        except OSError:
            # closing twice is harmless here
            pass


def pump(src, dst):
    try:
        while True:
            buf = src.recv(8192)
            if not buf:
                break
            dst.sendall(buf)
    except OSError:
        # either side went away: tear both down below
        pass
    finally:
        close_both(src, dst)


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        part = sock.recv(n - len(buf))
        if not part:
            return None
        buf += part
    return buf


def recv_packet(sock):
    """One handshake packet: before ACCEPT a packet's length is the header's
    first two bytes, on every protocol version."""
    head = recv_exact(sock, TNS_HEADER_LEN)
    if head is None:
        return None
    length = struct.unpack(">H", head[:2])[0]
    if length < TNS_HEADER_LEN:
        return None
    body = recv_exact(sock, length - TNS_HEADER_LEN)
    if body is None:
        return None
    return head + body


class Proxy:
    def __init__(self, ctx):
        self.ctx = ctx
        self.lock = threading.Lock()
        self.redirect_ports = {}  # (host, port) -> the local TLS port for it

    def listen(self, backend, port=0):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((LISTEN_HOST, port))
        srv.listen(8)
        threading.Thread(target=self.serve, args=(srv, backend), daemon=True).start()
        return srv.getsockname()[1]

    def serve(self, srv, backend):
        while True:
            try:
                client, _ = srv.accept()
            except OSError:
                break
            threading.Thread(target=self.handle, args=(client, backend),
                             daemon=True).start()

    def port_for(self, backend):
        with self.lock:
            port = self.redirect_ports.get(backend)
            if port is None:
                port = self.listen(backend)
                self.redirect_ports[backend] = port
            return port

    def rewrite_redirect(self, pkt):
        """Point a REDIRECT's address at a local TLS port forwarding to it.
        The body is the descriptor's length (ub2) and the descriptor."""
        body = pkt[TNS_HEADER_LEN:]
        if len(body) < 2:
            return pkt
        text = body[2:].decode("latin-1")
        addr = re.search(r"\(ADDRESS=.*?\)\)", text, re.IGNORECASE)
        scope = addr.group(0) if addr else text
        host = re.search(r"\(HOST=([^)]*)\)", scope, re.IGNORECASE)
        port = re.search(r"\(PORT=([0-9]+)\)", scope, re.IGNORECASE)
        if not host or not port:
            return pkt
        local = self.port_for((host.group(1), int(port.group(1))))
        print(f"REDIRECT {host.group(1)}:{port.group(1)} -> {LISTEN_HOST}:{local}",
              file=sys.stderr, flush=True)
        new_scope = scope.replace(host.group(0), f"(HOST={LISTEN_HOST})", 1)
        new_scope = new_scope.replace(port.group(0), f"(PORT={local})", 1)
        data = text.replace(scope, new_scope, 1).encode("latin-1")
        head = bytearray(pkt[:TNS_HEADER_LEN])
        struct.pack_into(">H", head, 0, TNS_HEADER_LEN + 2 + len(data))
        return bytes(head) + struct.pack(">H", len(data)) + data

    def handshake(self, back, tls):
        """Forward the listener's handshake replies, rewriting a REDIRECT,
        until the first reply that isn't a RESEND. False if a side closed."""
        while True:
            pkt = recv_packet(back)
            if pkt is None:
                return False
            kind = pkt[4]
            if kind == TNS_PT_REDIRECT:
                pkt = self.rewrite_redirect(pkt)
            tls.sendall(pkt)
            if kind != TNS_PT_RESEND:
                return True

    def handle(self, client, backend):
        try:
            tls = self.ctx.wrap_socket(client, server_side=True)
        except (ssl.SSLError, OSError):
            client.close()
            return
        try:
            back = socket.create_connection(backend)
        except OSError:
            tls.close()
            return
        t1 = threading.Thread(target=pump, args=(tls, back), daemon=True)
        t1.start()
        try:
            ok = self.handshake(back, tls)
        except OSError:
            ok = False
        if ok:
            pump(back, tls)
        else:
            close_both(back, tls)
        t1.join()


def main():
    backend = (sys.argv[1], int(sys.argv[2]))
    listen_port = int(sys.argv[3]) if len(sys.argv) > 3 else 0

    tmp = tempfile.mkdtemp(prefix="seer_tlsproxy_")
    cert, key = make_cert(tmp)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)

    proxy = Proxy(ctx)
    port = proxy.listen(backend, listen_port)
    print(f"PORT={port}", flush=True)
    print(f"CA={cert}", flush=True)
    threading.Event().wait()


if __name__ == "__main__":
    main()
