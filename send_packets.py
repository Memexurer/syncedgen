import requests
import socket
import select
import time
import struct
from time import sleep
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES

b69table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

header = bytes.fromhex("11 00 00 b9 11 00 03 e9 00 00 00 00 00 00 00 00 00 00 00 00 00 ff ff ff ff ff ff ff ff 00 00 00 98 aa 06 94 01 0a 70")
footer = bytes.fromhex("12 20 5f 76 df cc 7a f1 21 9e 8a cc 77 16 e7 25 13 7d 4a 99 e4 d6 97 56 bf e2 34 77 06 ad ae 40 c6 aa") # this is changing somehow - i have to rpelace it

if True:
    if False:
        openid = "1926974186469553284"
        token = "7c03f044b22672db24ab3203306d7aeb01949ddf"
    else:
        openid = "1926974186469552919"
        token = "0b27f35cefede7302228d66564fabf3aea3ea302"

    data = requests.get(f"https://usw2-realm.iegcom.com/v2/g6/auth/1962479523?authtype=4&os=5&channelid=131&sdkversion=&openid={openid}&token={token}&expired=0")

    data = data.json()["data"]
    ticket = data["login_ticket"]
    aes_key = data["login_key"]
else:
    ticket = "AdXCYvOIgACwuF9Ljea1LCv2KlmhotuMNlleuW9X3HFZMVbYgrdA7_HDSsNN8wWpSwhDeIneoSby_pM5Ap72hxSzyyMyzUdkguF34QnSLyJTaOtlN_8tHZr4lRXyIctk-Imb4HWvrigXMSpSToTUnA=="
    aes_key = "1234567812345678"

def custom_padding(plaintext):
    if len(plaintext) % 16 == 0:
        return plaintext
    else:
        return pad(plaintext, 16)
 
pf = "LevelInfinite_LevelInfinite-Windows-windows-Windows-LevelInfinite-aec575b4b14c87016dce3764fea239fb-1926974186469552919"
pfkey = "c33dfe291b65bd248a1f0f486f3976e1"
xwid = "79372dd523ebe2f13263732a31a4edff4021bd2f14afdc806c402bf96c33bf" # thats my hwid
# didnt do auto hwid generation because it would be a waste of time (i didnt think that i would go so far with this tbh)

def b69decode(b69_str, decode_len=0):
    
    if not b69_str:
        return b"", -1
    
    padding = 0
    if b69_str[-1] == '=':
        padding += 1
    if b69_str[-2] == '=':
        padding += 2

    decoded = b""
    quad_pos = 0
    leftbits = 0
    
    for pos, c in enumerate(b69_str):
        if c == '=':
            break
        try:
            i = b69table.index(c)
        except ValueError:
            return b"", -3
            
        if pos % 4 == 0:
            leftbits = i << 2
        elif pos % 4 == 1:
            leftbits |= i >> 4
            decoded += bytes([leftbits])
            leftbits = (i & 0xF) << 4
        elif pos % 4 == 2:
            leftbits |= i >> 2
            decoded += bytes([leftbits])
            leftbits = (i & 0x3) << 6
        else:
            leftbits |= i
            decoded += bytes([leftbits])
            leftbits = 0
            
        quad_pos += 1
        if quad_pos == 4:
            quad_pos = 0
            
    if padding == 1:
        decoded = decoded[:-1]
    elif padding == 2:
        decoded = decoded[:-2]

    if decode_len > 0 and len(decoded) != decode_len:
        return b"", -4
            
    return decoded
        
def create_packet(ticket):
    return header + b69decode(ticket) + footer

handshake_packet = create_packet(ticket)
# handshake_packet = bytes.fromhex("11 00 00 b9 11 00 03 e9 00 00 00 00 00 00 00 00 00 00 00 00 00 ff ff ff ff ff ff ff ff 00 00 00 98 aa 06 94 01 0a 70 01 d5 c2 62 f3 88 80 00 b0 b8 5f 4b 8d e6 b5 2c a7 17 0b ec 54 c8 3e 29 2b 37 31 85 45 88 33 5f 63 37 4d d4 d6 85 5e 81 bb 8c 8c 1b ad c6 01 cf 39 68 06 aa 69 10 2e 24 7f ba 11 33 55 ed 1c dc df 18 1d 8e 80 66 a1 86 dd fe b6 0d dd 45 f2 d5 cd 27 b9 1a 73 da 3c 19 41 9c 90 7a 7e 58 b1 f7 5b 9c 2d b6 b0 ed 06 97 9b 00 57 9a ce df bd aa 12 20 5f 76 df cc 7a f1 21 9e 8a cc 77 16 e7 25 13 7d 4a 99 e4 d6 97 56 bf e2 34 77 06 ad ae 40 c6 aa")

client_socket = socket.socket() 
client_socket.connect(("52.137.93.14", 15100))
client_socket.send(handshake_packet)

# first packet - always 201 in length (setup encrypt)
handshake = client_socket.recv(4096)

session_id = handshake[12:20]
print("got session id: " + session_id.hex())

encrypted_cooler = handshake[-64:]
cipher = AES.new(aes_key.encode(), AES.MODE_CBC, b'\00' * AES.block_size)
handshake = cipher.decrypt(encrypted_cooler) # update with decrypted

aes_key = handshake[12:12+32] # key length: 32
aes_key = aes_key[:16]

cipher_decrypt = AES.new(aes_key, AES.MODE_CBC, b'\00' * AES.block_size) # but we cut it into 16 bytes...
cipher_encrypt = AES.new(aes_key, AES.MODE_CBC, b'\00' * AES.block_size) # but we cut it into 16 bytes...
print("got new aes key: " + aes_key.decode())

# second packet -idk!
print(cipher_decrypt.decrypt(custom_padding(client_socket.recv(4096)[4:])).hex())

def send_packet(plain): # sends a packet with 12 header
    plain = custom_padding(plain)
    print(plain.hex(bytes_per_sep=2))
    re_encrypted = cipher_encrypt.encrypt(plain)

    odjonc = 0
    if len(re_encrypted) % 16 == 0:
        odjonc = 16
    
    full_packet = bytes.fromhex("21 00") + struct.pack(">H", len(re_encrypted) + 4 - odjonc) + re_encrypted # +4 or without 
    client_socket.send(full_packet)

# second part - send second handshake packet
# packet = bytes.fromhex("12 00 00 40 00 00 00 01 10 03 F5 58 A4 4A 4B F2 0F 41 72 6B 50 6C 61 79 65 72 45 6E 74 69 74 79 FF FF FF FF FF FF FF FF 00 00 00 A9 0A 1B 0A 09 65 6E 74 69 74 79 5F 69 64 12 0E 35 34 30 37 39 30 31 35 37 39 39 31 37 39 0A 12 0A 06 6D 73 67 5F 69 64 12 08 39 31 30 30 38 39 35 31 0A 0D 0A 08 6D 73 67 5F 74 79 70 65 12 01 31 0F 44 45 53 4B 54 4F 50 2D 51 46 39 43 4A 42 31 00 05 70 66 6B 65 79 00 00 00 02 70 66 00 00 00 04 0F 09 08 05 14 14 14 14 02 65 6E 00 3E 37 39 33 37 32 64 64 35 32 33 65 62 65 32 66 31 33 32 36 33 37 33 32 61 33 31 61 34 65 64 66 66 34 30 32 31 62 64 32 66 31 34 61 66 64 63 38 30 36 63 34 30 32 62 66 39 36 63 33 33 62 66 00 00 00 00 0A 00 00 00 01 00 00 00 8F A1 03 00 02 00 00 00 7F 00 00 00 03 00 00 00 67 00 00 00 04 00 00 00 66 00 00 00 05 00 00 00 6A 00 00 00 06 06 06 14 06 28 06 14 06 14 32 2A 01")
packet = bytes.fromhex("11000024110003EF000000021003F56D3ECE8EF50F41726B506C61796572456E74697479FFFFFFFFFFFFFFFF0000013D0A1B0A09656E746974795F6964120E35353737303135333331363639350A0D0A086D73675F747970651201310A120A066D73675F6964120839313030383935310F4445534B544F502D514639434A42310002706600764C6576656C496E66696E6974655F4C6576656C496E66696E6974652D57696E646F77732D77696E646F77732D57696E646F77732D4C6576656C496E66696E6974652D61656335373562346231346338373031366463653337363466656132333966622D31393236393734313836343639353532393139000570666B6579002063333364666532393162363562643234386131663066343836663339373665310004A5A22B251414141402656E003E373933373264643532336562653266313332363337333261333161346564666634303231626432663134616664633830366334303262663936633333626600000A00000001000000C6B40300020000001301000003000000650000000400000064000000050000006800000006060614062806140614322A01")
 
if len(pf) != 118 or len(pfkey) != 32 or len(xwid) != 62:
    print("invalid pf/key")
    exit(0)


packet_session_id = packet[packet.index(b"\x10\x03"):packet.index(b"\x10\x03")+8]
print("replacing session id: " + packet_session_id.hex())
packet = packet.replace(packet_session_id, session_id)

if False: # our weird packet doesnt have pf, pfkey and en
    pf_index = packet.index(b"pf\x00\x76") + 4 # pf\x00\x76
    pfkey_index = packet.index(b"pfkey\x00\x20") + 7 # pfkey\x00\x20

    packet = packet.replace(packet[pf_index:pf_index+118], pf.encode())
    packet = packet.replace(packet[pfkey_index:pfkey_index+32], pfkey.encode())

xwid_index = packet.index(b"en\x00\x3e") + 4 # en\x00\x3e
old_xwid = packet[xwid_index:xwid_index+62]
print("old xwid: " + old_xwid.decode())
packet = packet.replace(old_xwid, xwid.encode())


print("the packet which we want:")
send_packet(packet)


# Wait for events on the sockets
while True:
    ready = select.select([client_socket], [], [])
    if ready:
        # Handle incoming data
        data = client_socket.recv(1024)
        print(data)

# print(client_socket.recv(4096))

# # keep alive - always responds

# client_socket.send(bytes.fromhex('11000024110003ef000000021003f558a44a48c500ffffffffffffffff00000003da0600'))
# print(client_socket.recv(4096))


# send_packet(
#     bytes.fromhex("a89c26720c0c0c091c0ff9451b04fb670f41726b506c61796572456e74697479ffffffffffffffff000000080a140a066d73675f6964120a313739353936363931380a1b0a09656e746974795f6964120e35323438333433363537353834320a0d0a086d73675f7479706512013102010004000428010a0a0a0a0a0a0a0a0a0acd3ebe2ac076413ad79705f2166d04fc")
# )
# print(client_socket.recv(4096))

# client_socket.close()
