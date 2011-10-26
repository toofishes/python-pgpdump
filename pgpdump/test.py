import base64
from unittest import TestCase

from pgpdump import AsciiData, BinaryData
from pgpdump.packet import (TAG_TYPES, SignaturePacket,
        old_tag_length, new_tag_length)

class ParseTestCase(TestCase):
    def test_parse_exception(self):
        with self.assertRaises(Exception):
            BinaryData(None)

    def check_sig_packet(self, packet, length, version, typ,
            creation_time, key_id, pub_alg, hash_alg):
        '''Helper method for quickly verifying several fields on a signature
        packet.'''
        self.assertEqual(2, packet.raw)
        self.assertEqual(length, packet.length)
        self.assertEqual(version, packet.sig_version)
        self.assertEqual(typ, packet.raw_sig_type)
        self.assertEqual(creation_time, packet.creation_time)
        self.assertEqual(key_id, packet.key_id)
        self.assertEqual(pub_alg, packet.raw_pub_algorithm)
        self.assertEqual(hash_alg, packet.raw_hash_algorithm)

    def test_parse_single_sig_packet(self):
        base64_sig = b"iEYEABECAAYFAk6A4a4ACgkQXC5GoPU6du1ATACgodGyQne3Rb7"\
                b"/eHBMRdau1KNSgZYAoLXRWt2G2wfp7haTBjJDFXMGsIMi"
        sig = base64.b64decode(base64_sig)
        data = BinaryData(sig)
        packets = list(data.packets())
        self.assertEqual(1, len(packets))
        sig_packet = packets[0]
        self.assertFalse(sig_packet.new)
        self.check_sig_packet(sig_packet, 70, 4, 0, 1317069230,
                0x5C2E46A0F53A76ED, 17, 2)
        self.assertEqual(2, len(sig_packet.subpackets))

    def test_parse_ascii_sig_packet(self):
        asc_data = b'''
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.4.11 (GNU/Linux)

iEYEABECAAYFAk6neOwACgkQXC5GoPU6du23AQCgghWjIFgBazXWIZNj4PGnkuYv
gMsAoLGOjudliDT9u0UqxN9KeJ22Jdne
=KYol
-----END PGP SIGNATURE-----'''
        data = AsciiData(asc_data)
        packets = list(data.packets())
        self.assertEqual(1, len(packets))
        sig_packet = packets[0]
        self.assertFalse(sig_packet.new)
        self.check_sig_packet(sig_packet, 70, 4, 0, 1319598316,
                0x5C2E46A0F53A76ED, 17, 2)
        self.assertEqual(2, len(sig_packet.subpackets))

    def test_parse_linus_binary(self):
        with open('linus.gpg', 'rb') as keyfile:
            rawdata = keyfile.read()
        data = BinaryData(rawdata)
        packets = list(data.packets())
        self.assertEqual(44, len(packets))
        seen = 0
        for packet in packets:
            # all 44 packets are of the known 'old' variety
            self.assertFalse(packet.new)
            if isinstance(packet, SignaturePacket):
                # a random signature plucked off the key
                if packet.key_id == 0xE7BFC8EC95861109:
                    seen += 1
                    self.check_sig_packet(packet, 540, 4, 0x10, 1319560576,
                            0xE7BFC8EC95861109, 1, 8)
                    self.assertEqual(2, len(packet.subpackets))
                # a particularly dastardly sig- a ton of hashed sub parts,
                # this is the "positive certification packet"
                elif packet.key_id == 0x79BE3E4300411886 and \
                        packet.raw_sig_type == 0x13:
                    seen += 1
                    self.check_sig_packet(packet, 312, 4, 0x13, 1316554898,
                            0x79BE3E4300411886, 1, 2)
                    self.assertEqual(8, len(packet.subpackets))
                # another sig from key above, the "subkey binding sig"
                elif packet.key_id == 0x79BE3E4300411886 and \
                        packet.raw_sig_type == 0x18:
                    seen += 1
                    self.check_sig_packet(packet, 287, 4, 0x18, 1316554898,
                            0x79BE3E4300411886, 1, 2)
                    self.assertEqual(3, len(packet.subpackets))

        self.assertEqual(3, seen)

    def test_parse_linus_ascii(self):
        with open('linus.asc', 'rb') as keyfile:
            rawdata = keyfile.read()
        data = AsciiData(rawdata)
        packets = list(data.packets())
        self.assertEqual(44, len(packets))
        # Note: we could do all the checks we did above in the binary version,
        # but this is really only trying to test the AsciiData extras, not the
        # full stack.

class PacketTestCase(TestCase):
    def test_lookup_type(self):
        self.assertEqual("Signature Packet", TAG_TYPES[2][0])

    def test_old_tag_length(self):
        data = [
            ((1, 2),    [0xb0, 0x02]),
            ((1, 70),   [0x88, 0x46]),
            ((2, 284),  [0x89, 0x01, 0x1c]),
            ((2, 525),  [0xb9, 0x02, 0x0d]),
            ((2, 1037), [0xb9, 0x04, 0x0d]),
        ]
        for expected, invals in data:
            self.assertEqual(expected, old_tag_length(invals, 0))

    def test_new_tag_length(self):
        data = [
            ((0, 2),    [0x02]),
            ((0, 16),   [0x10]),
            ((0, 166),  [0xa6]),
            ((0, 168),  [0xa8]),
            ((1, 3923), [0xce, 0x93]),
            ((1, 5119), [0xd3, 0x3f]),
            ((1, 6476), [0xd8, 0x8c]),
            ((4, 26306), [0xff, 0x00, 0x00, 0x66, 0xc2]),
        ]
        for expected, invals in data:
            self.assertEqual(expected, new_tag_length(invals))
