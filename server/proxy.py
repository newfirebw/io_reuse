#!/usr/bin/python
# -*- coding: UTF-8 -*-

import sys
import socket


def main(bind_port, trans_port):
    src, dst = None, None
    try:
        src = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        src.bind(("0.0.0.0", bind_port))
        src.listen(256)

        dst = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        dst.connect(('127.0.0.1', trans_port))

        while True:
            conn, (addr, port) = src.accept()
            data = conn.recv(4096)
            dst.send(data)
            recv_data = dst.recv(4096)
            src.send(recv_data)
    except KeyboardInterrupt as e:
        if src:
            src.close()
        if dst:
            dst.close()


if __name__ == '__main__':
    main(12138, int(sys.argv[1]))
