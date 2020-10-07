import socket
import binascii
from hashlib import sha1
from random import randint
from struct import unpack
from socket import inet_ntoa
from threading import Timer, Thread
from time import sleep
from collections import deque
import time
import random
from threading import Timer
import heapq

def entropy(length):
    return "".join(chr(randint(0, 255)) for _ in xrange(length))

def random_id():
    h = sha1()
    h.update(entropy(20))
    return h.digest()

SELF_NODEID = random_id()

TID_LENGTH = 2
TOKEN_LENGTH = 2


def generate_find_node_message(tid=None):
    if tid == None:
        tid = entropy(TID_LENGTH)
    msg = {
        "t": tid,
        "y": "q",
        "q": "find_node",
        "a": {
            "id": SELF_NODEID,
            "target": random_id()
        }
    }
    return msg

def decode_nodes(nodes):
    n = []
    length = len(nodes)
    if (length % 26) != 0:
        return n

    for i in range(0, length, 26):
        nid = nodes[i:i + 20]
        ip = inet_ntoa(nodes[i + 20:i + 24])
        port = unpack("!H", nodes[i + 24:i + 26])[0]
        n.append((nid, ip, port))

    return n


def generate_ping_message():
    tid = entropy(TID_LENGTH)
    msg = {
        "t": "xX",
        "y": "q",
        "q": "ping",
        "a": {
            "id": SELF_NODEID,
        }
    }
    return msg