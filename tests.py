from nativeipc import Cipher

def test_reencryption(cipher, packet):
    packet_decrypted = cipher.decrypt(packet[4:])
    packet_reencrypted = packet[:4] + cipher.encrypt(packet_decrypted)
    packet_reencrypted_custom = cipher.construct_packet(packet_decrypted)

    try:
        assert packet == packet_reencrypted
        assert packet == packet_reencrypted_custom
    except AssertionError:
        print("-- THE PACKET IS BROKEN -- ")
        print(f"orig packet: {len(packet)}, reencrypted packet: {len(packet_reencrypted)}, reencrypted custom: {len(packet_reencrypted_custom)}")
        print(packet.hex())
        print(packet_reencrypted.hex())
        print(packet_reencrypted_custom.hex())
        exit(1)