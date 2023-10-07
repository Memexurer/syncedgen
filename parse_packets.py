import json
import struct
import codecs
import requests
import struct
from nativeipc import Cipher
from tests import test_reencryption


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


packets = json.loads(open('packets.json', 'rb').read())
# packets = requests.get("http://127.0.0.1:8081/flows/4ce993e9-0afa-4739-ba0f-f03b4d77063b/messages/content/Auto.json").json() # get packets straight from mitmproxy

i = 0

cipher = Cipher(b"1234567812345678")

for packet in packets:
    data = ''.join([line[1][1] for line in packet['lines']]).replace(" ", "")

    sent_from_game = packet["from_client"]


    protobuf = "ffffffffffffffff" in data
    raw_data = bytes.fromhex(data)
    state = data[0] # 1 - protobuf, 2 - encrypted something

    i += 1

    if i == 2: # second packet - response to handshake
        encrypted_cooler = raw_data[-64:]
        cipher.key = cipher.decrypt(encrypted_cooler)[12:12+32]
        print("cipher updated: " + cipher.key.decode())


    packet = raw_data
    decrypted = False
    lenk = len(raw_data)

    if state == "2":
        test_reencryption(cipher, raw_data)
        raw = cipher.decrypt(raw_data[4:])
        packet = bytearray(raw_data[:4] + raw)
        lenk = len(raw)
        decrypted = True


    print((">out(from game)" if sent_from_game else "<in(from server) ") + " type: " + ("protobuf" if state == "1" else "encrypted") + f" (len: {lenk})")
    packet = packet[:struct.unpack(">h",  packet[2:4])[0]]
    
    try:
        if sent_from_game:
            header = unpack_cshead(packet)
        else:
            header = unpack_cshead(packet)
        print("header:", header)
        print("contents:", packet.hex())
    except:
        print("failed to unpack cshead :()")