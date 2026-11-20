import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

import socket
import sys
HOST = "192.168.1.55"
PORT = 3333

class gestionSetup:

    def __init__(self):
        self.host = HOST
        self.port = PORT
        
    def actionSetupAES(self, aes_key):
        try:
            with socket.create_connection((HOST, PORT), timeout=5) as sock:            
                sock.sendall(aes_key.hex().upper().encode())
                sock.sendall("\n".encode())
        except Exception as e:
            print(f"PV message : {e}")

    def actionSetupRSA(self, clefPrive, clefPublic):
        try:
            with socket.create_connection((HOST, PORT), timeout=5) as sock:   
                print("d :", hex(clefPrive.d).encode())           
                sock.sendall("\n Priv".encode())
                sock.sendall(hex(clefPrive.d).encode())
                sock.sendall("\n Pub".encode())
                #print("d :", hex(self.clefPrive.d))      # pycryptodome
                #print("n :", hex(self.clefPublic.n))
                sock.sendall(hex(clefPublic.n).encode())
                sock.sendall("\n".encode())
        except Exception as e:
            print(f"PV message : {e}")        