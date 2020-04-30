import socket
import base64
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_v1_5
import simplejson

from os import getcwd
import sqlite3

from ast import literal_eval


def databaseTool(sql: str):
    try:
        conn = sqlite3.connect(getcwd() + '/MyPass.db')
        c = conn.cursor()
        cursor = c.execute(sql)
        list_return = []
        for row in cursor:
            list_return.append(row)

        conn.commit()
        conn.close()
        return list_return
    except:
        return False


def rsa_long_encrypt(msg, length=200):
    """
    单次加密串的长度最大为 (key_size/8)-11
    1024bit的证书用100， 2048bit的证书用 200
    """
    recipient_key = RSA.import_key(
        open("public.pem").read()
    )
    rsa = PKCS1_v1_5.new(recipient_key)
    res = []
    for i in range(0, len(msg), length):
        print(len(msg))
        print(i)
        res.append(base64.b64encode(rsa.encrypt(msg[i:i+length].encode())).decode())
    return res


def rsa_long_decrypt(msg, length=256):
    """
    1024bit的证书用128，2048bit证书用256位
    """
    recipient_key = RSA.import_key(
        open("private.pem").read()
    )
    rsa = PKCS1_v1_5.new(recipient_key)
    res = []
    msg = literal_eval(base64.b64decode(msg).decode())
    for i in msg:
        res.append(rsa.decrypt(base64.b64decode(i.encode()), None).decode("utf-8", "ignore"))
    return "".join(res)






sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(('localhost', 4201))
sock.listen(5)

recipient_key = RSA.import_key(
    open("private.pem").read()
)
rsa = PKCS1_v1_5.new(recipient_key)

while True:
    conn, addr = sock.accept()  # socket.accept()：返回(conn,address)对，其中conn是新的socket对象，在其上可以发送和接收数据；address是另一端的socket地址

    conn.settimeout(5)
    cipher_text = conn.recv(4096)  # 使用sock.accept()创建的socket对象
    data_list = databaseTool(rsa_long_decrypt(cipher_text))
    return_list = []
    if(len(data_list)!=0):
        for row in data_list:
            return_list.append(row[3])
            print(row)
            print(row[3])

    conn.send(str(return_list).encode())
    conn.close()
