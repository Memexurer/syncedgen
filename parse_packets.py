import json
import struct
from lz4.frame import compress, decompress
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import codecs
import requests
import struct


def unpack_cshead(data, endianess='>', xd=False): # INCOMING packets are marked by >
    cshead = {}

    # Map struct fields to Python dict using unsigned  
    cshead['packet_type'] = hex(struct.unpack(endianess + 'H', data[0:2])[0])
    cshead['a'] = hex(struct.unpack(endianess + 'B', data[2:3])[0])
    cshead['b'] = hex(struct.unpack(endianess + 'B', data[3:4])[0])
    cshead['c'] = hex(struct.unpack(endianess + 'H', data[4:6])[0] ) 
    cshead['d'] = hex(struct.unpack(endianess + 'I', data[6:10])[0] )

    session_id = data[12:20]
    if xd:
        session_id = fix_dupson(data[12:20])
    cshead['session_id'] = hex(struct.unpack(endianess + 'Q', session_id)[0])
    cshead['f'] = data[20:148]  

    # cshead['g'] = hex(struct.unpack(endianess + 'Q', data[146:154])[0])
    # cshead['h'] = hex(struct.unpack(endianess + 'I', data[154:158])[0])

    return cshead

def fix_dupson(dupik):
    i = 0

    dupek = ""
    for hex_digit in dupik.hex()[i:]:
        if i > 16:
            break

        if i % 2 == 0:
            dupek += hex_digit
        else:
            digit = int(hex_digit, base=16)
            if digit < 8:
                digit = digit + 8
            else:
                digit = digit - 8

            dupek += hex(digit)[2]

        i += 1
    
    return bytes.fromhex(dupek)


codecs.register_error("strict", codecs.ignore_errors)

# https://soundcloud.com/maikaii/kyoshin


# packets = json.loads(open('packets2.json', 'rb').read())
packets = requests.get("http://127.0.0.1:8081/flows/4ce993e9-0afa-4739-ba0f-f03b4d77063b/messages/content/Auto.json").json() # get packets straight from mitmproxy

i = 0

cipher = AES.new("1234567812345678".encode(), AES.MODE_CBC, b'\00' * AES.block_size)

for packet in packets:
    data = ''.join([line[1][1] for line in packet['lines']]).replace(" ", "")

    sent_from_game = packet["from_client"]


    protobuf = "ffffffffffffffff" in data
    raw_data = bytes.fromhex(data)
    state = data[0] # 1 - protobuf, 2 - encrypted something

    i += 1

    if i == 2: # second packet - response to handshake
        encrypted_cooler = raw_data[-64:]
        key = cipher.decrypt(encrypted_cooler)[12:12+32]
        cipher = AES.new(key[:16], AES.MODE_CBC, b'\00' * AES.block_size)
        print("cipher updated: " + key.decode())


    packet = raw_data
    decrypted = False
    lenk = len(raw_data)

    if state == "2":
        try:
            raw = cipher.decrypt(pad(raw_data[4:], 16))
            packet = bytearray(raw_data[:4] + raw)
            for i in range(0, 40, 2):
                pass
                # packet[i] = (packet[i] - 8) % 16
            lenk = len(raw)
            decrypted = True
        except Exception as e:
            print("siusiak: " + str(e) + " " + str((len(raw_data) - 4) % 16))
            pass


    print((">out(from game)" if sent_from_game else "<in(from server) ") + " type: " + ("protobuf" if state == "1" else "encrypted") + f" (len: {lenk})")
    packet = packet[:struct.unpack(">h",  packet[2:4])[0]]
    
    try:
        if sent_from_game:
            header = unpack_cshead(packet, xd=True)
        else:
            header = unpack_cshead(packet)
        print("header:", header)
        print("contents:", packet.hex())
    except:
        print("failed to unpack cshead :()")