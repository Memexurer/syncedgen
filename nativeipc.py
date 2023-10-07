import win32file, win32pipe
import struct
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

pipe_name = r'\\.\pipe\fallingpipe'

NATIVE = True

def send_message(mess):
    open_mode = win32pipe.PIPE_ACCESS_DUPLEX | win32file.FILE_FLAG_OVERLAPPED
    pipe_handle = win32file.CreateFile(pipe_name, open_mode, 0, None, 
                                        win32file.OPEN_EXISTING, 0, None)
    win32file.WriteFile(pipe_handle, mess) 
    resp = win32file.ReadFile(pipe_handle, 65536)[1]
    win32file.CloseHandle(pipe_handle)

    return resp

def _aes_native(key, data, encrypt):
    prefix = b"\x01" if encrypt else b"\x00"
    data = send_message(prefix + struct.pack("32sI{}s".format(len(data)), key, len(data), data))
    return data

def _aes_decrypt_legacy(key, data):
    print("oh yeah we're definetly doing that")
    return send_message(b"\x00" + struct.pack("32sI{}s".format(len(data)), key, len(data), data))

def _aes_decrypt_native(key, data):
    return _aes_native(key, data, False)

def _aes_encrypt_native(key, data):
    return _aes_native(key, data, True)

def aes_decrypt(cipher_key, content):
    if len(content) % 16 != 0:
        content = pad(content, 16)

    if NATIVE: # if native
        return _aes_decrypt_native(cipher_key, content)
    else:
        cipher = AES.new(cipher_key[:16], AES.MODE_CBC, b'\00' * AES.block_size)
        return cipher.decrypt(content)

def aes_encrypt(cipher_key, content):
    pad_amount = len(content) % 16
    if pad_amount != 0:
        content = pad(content, 16)

    if True: # if native
        return _aes_encrypt_native(cipher_key, content)
    else:
        cipher = AES.new(cipher_key[:16], AES.MODE_CBC, b'\00' * AES.block_size)
        return cipher.encrypt(content)[:len(content) - pad_amount]

def construct_packet(re_encrypted):
    odjonc = 0

    full_packet = bytes.fromhex("21 00") + struct.pack(">H", len(re_encrypted) + 4 - odjonc) + re_encrypted # +4 or without 
    return full_packet

class Cipher():
    def __init__(self, key):
        self.key = key

    def decrypt(self, content):
        return aes_decrypt(self.key, content)

    def encrypt(self, content):
        return aes_encrypt(self.key, content)
    
    def construct_packet(self, content):
        return construct_packet(
            self.encrypt(content)
        )