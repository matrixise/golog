#!/usr/bin/env python
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto("Hello", ("127.0.0.1", 5433))
