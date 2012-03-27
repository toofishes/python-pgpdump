import base64
from datetime import datetime
from itertools import repeat
import os.path
from unittest import TestCase

from pgpdump import AsciiData, BinaryData
from pgpdump.packet import (TAG_TYPES, SignaturePacket, PublicKeyPacket,
        PublicSubkeyPacket, UserIDPacket, old_tag_length, new_tag_length)
from pgpdump.utils import crc24, get_int8, get_mpi, get_key_id, same_key


def load_data(filename):
    full_path = os.path.join('testdata', filename)
    with open(full_path, 'rb') as fileobj:
        data = fileobj.read()
    return data


class UtilsTestCase(TestCase):
    def test_crc24(self):
        self.assertEqual(0xb704ce, crc24(bytearray(b"")))
        self.assertEqual(0x21cf02, crc24(bytearray(b"123456789")))
        self.assertEqual(0xe84567, crc24(repeat(0, 1024 * 1024)))

    # get_int2, get_int4 are tested plenty by actual code

    def test_int8(self):
        data = [
            (0, [0x00] * 8),
            (0x0a0b0c0d, (0x00, 0x00, 0x00, 0x00, 0x0a, 0x0b, 0x0c, 0x0d)),
            (0x0a0b0c0d << 32, bytearray(b'\x0a\x0b\x0c\x0d\x00\x00\x00\x00')),
        ]
        for expected, invals in data:
            self.assertEqual(expected, get_int8(invals, 0))

    def test_mpi(self):
        data = [
            (1,   3, (0x00, 0x01, 0x01)),
            (511, 4, (0x00, 0x09, 0x01, 0xff)),
            (65537, 5, bytearray(b'\x00\x11\x01\x00\x01')),
        ]
        for expected, offset, invals in data:
            self.assertEqual((expected, offset), get_mpi(invals, 0))

    def test_key_id(self):
        self.assertEqual(b"5C2E46A0F53A76ED",
                get_key_id(b"\\.F\xa0\xf5:v\xed", 0))

    def test_same_key(self):
        fprint = b"A5CA9D5515DC2CA73DF748CA5C2E46A0F53A76ED"
        key_id = b"5C2E46A0F53A76ED"
        short = b"F53A76ED"
        different = b"A5CA9D55"

        self.assertTrue(same_key(fprint, fprint))
        self.assertTrue(same_key(fprint, key_id))
        self.assertTrue(same_key(fprint, short))

        self.assertTrue(same_key(key_id, fprint))
        self.assertTrue(same_key(key_id, key_id))
        self.assertTrue(same_key(key_id, short))

        self.assertTrue(same_key(short, fprint))
        self.assertTrue(same_key(short, key_id))
        self.assertTrue(same_key(short, short))

        self.assertFalse(same_key(fprint, different))
        self.assertFalse(same_key(key_id, different))
        self.assertFalse(same_key(short, different))
        self.assertFalse(same_key(different, fprint))
        self.assertFalse(same_key(different, key_id))
        self.assertFalse(same_key(different, short))


class ParseTestCase(TestCase):
    def test_parse_empty(self):
        with self.assertRaises(Exception):
            BinaryData(None)

    def test_parse_short(self):
        with self.assertRaises(Exception):
            BinaryData([0x00])

    def test_parse_invalid(self):
        with self.assertRaises(Exception):
            BinaryData([0x00, 0x00])

    def check_sig_packet(self, packet, length, version, typ,
            creation_time, key_id, pub_alg, hash_alg):
        '''Helper method for quickly verifying several fields on a signature
        packet.'''
        self.assertEqual(2, packet.raw)
        self.assertEqual(length, packet.length)
        self.assertEqual(version, packet.sig_version)
        self.assertEqual(typ, packet.raw_sig_type)
        self.assertEqual(creation_time, packet.raw_creation_time)
        self.assertEqual(key_id, packet.key_id)
        self.assertEqual(pub_alg, packet.raw_pub_algorithm)
        self.assertEqual(hash_alg, packet.raw_hash_algorithm)

        # test some of the lazy lookup methods
        if typ == 0x18:
            self.assertEqual("Subkey Binding Signature", packet.sig_type)
        if pub_alg == 17:
            self.assertEqual("DSA Digital Signature Algorithm",
                    packet.pub_algorithm)
        if hash_alg == 2:
            self.assertEqual("SHA1", packet.hash_algorithm)

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
                b"5C2E46A0F53A76ED", 17, 2)
        self.assertEqual(2, len(sig_packet.subpackets))
        self.assertEqual(["Signature Creation Time","Issuer"],
                [sp.name for sp in sig_packet.subpackets])

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
                b"5C2E46A0F53A76ED", 17, 2)
        self.assertEqual(2, len(sig_packet.subpackets))

    def test_parse_bad_crc(self):
        asc_data = b'''
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.4.11 (GNU/Linux)

iEYEABECAAYFAk6neOwACgkQXC5GoPU6du23AQCgghWjIFgBazXWIZNj4PGnkuYv
gMsAoLGOjudliDT9u0UqxN9KeJ22JdnX
=KYol
-----END PGP SIGNATURE-----'''
        self.assertRaises(Exception, AsciiData, asc_data)

    def test_parse_v3_sig(self):
        asc_data = b'''
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v2.0.18 (GNU/Linux)

iD8DBQBPWDfGXC5GoPU6du0RAq6XAKC3TejpiBsu3pGF37Q9Id/vPzoFlwCgtwXE
E/GGdt/Cn5Rr1G933H9nwxo=
=aJ6u
-----END PGP SIGNATURE-----'''
        data = AsciiData(asc_data)
        packets = list(data.packets())
        self.assertEqual(1, len(packets))
        sig_packet = packets[0]
        self.assertFalse(sig_packet.new)
        self.check_sig_packet(sig_packet, 63, 3, 0, 1331181510,
                b"5C2E46A0F53A76ED", 17, 2)
        self.assertEqual(b'\xae\x97', sig_packet.hash2)
        self.assertEqual(0, len(sig_packet.subpackets))

    def test_parse_ascii_clearsign(self):
        '''This is a clearsigned document with an expiring signature, so tests
        both the ignore pattern in AsciiData as well as additional signature
        subpackets.'''
        asc_data = load_data('README.asc')
        data = AsciiData(asc_data)
        packets = list(data.packets())
        self.assertEqual(1, len(packets))
        sig_packet = packets[0]
        self.assertFalse(sig_packet.new)
        self.assertEqual(3, len(sig_packet.subpackets))
        self.check_sig_packet(sig_packet, 76, 4, 1, 1332874080,
                b"5C2E46A0F53A76ED", 17, 2)
        # raw expires time is in seconds from creation date
        self.assertEqual(345600, sig_packet.raw_expiration_time)
        expires = datetime(2012, 3, 31, 18, 48, 00)
        self.assertEqual(expires, sig_packet.expiration_time)

    def test_parse_linus_binary(self):
        rawdata = load_data('linus.gpg')
        data = BinaryData(rawdata)
        packets = list(data.packets())
        self.assertEqual(44, len(packets))
        seen = 0
        for packet in packets:
            # all 44 packets are of the known 'old' variety
            self.assertFalse(packet.new)

            if isinstance(packet, SignaturePacket):
                # a random signature plucked off the key
                if packet.key_id == b"E7BFC8EC95861109":
                    seen += 1
                    self.check_sig_packet(packet, 540, 4, 0x10, 1319560576,
                            b"E7BFC8EC95861109", 1, 8)
                    self.assertEqual(2, len(packet.subpackets))
                # a particularly dastardly sig- a ton of hashed sub parts,
                # this is the "positive certification packet"
                elif packet.key_id == b"79BE3E4300411886" and \
                        packet.raw_sig_type == 0x13:
                    seen += 1
                    self.check_sig_packet(packet, 312, 4, 0x13, 1316554898,
                            b"79BE3E4300411886", 1, 2)
                    self.assertEqual(8, len(packet.subpackets))
                # another sig from key above, the "subkey binding sig"
                elif packet.key_id == b"79BE3E4300411886" and \
                        packet.raw_sig_type == 0x18:
                    seen += 1
                    self.check_sig_packet(packet, 287, 4, 0x18, 1316554898,
                            b"79BE3E4300411886", 1, 2)
                    self.assertEqual(3, len(packet.subpackets))

            elif isinstance(packet, PublicSubkeyPacket):
                seen += 1
                self.assertEqual(4, packet.pubkey_version)
                self.assertEqual(1316554898, packet.raw_creation_time)
                self.assertEqual(1, packet.raw_pub_algorithm)
                self.assertIsNotNone(packet.modulus)
                self.assertEqual(65537, packet.exponent)
                self.assertEqual(b"012F54CA", packet.fingerprint[32:])

            elif isinstance(packet, PublicKeyPacket):
                seen += 1
                self.assertEqual(4, packet.pubkey_version)
                self.assertEqual(1316554898, packet.raw_creation_time)
                self.assertEqual(1, packet.raw_pub_algorithm)
                self.assertEqual("RSA Encrypt or Sign", packet.pub_algorithm)
                self.assertIsNotNone(packet.modulus)
                self.assertEqual(65537, packet.exponent)
                self.assertEqual(b"ABAF11C65A2970B130ABE3C479BE3E4300411886",
                        packet.fingerprint)
                self.assertEqual(b"79BE3E4300411886", packet.key_id)

            elif isinstance(packet, UserIDPacket):
                seen += 1
                self.assertEqual("Linus Torvalds", packet.user_name)
                self.assertEqual("torvalds@linux-foundation.org",
                        packet.user_email)

        self.assertEqual(6, seen)

    def test_parse_linus_ascii(self):
        rawdata = load_data('linus.asc')
        data = AsciiData(rawdata)
        packets = list(data.packets())
        self.assertEqual(44, len(packets))
        # Note: we could do all the checks we did above in the binary version,
        # but this is really only trying to test the AsciiData extras, not the
        # full stack.

    def test_parse_dan(self):
        '''This key has DSA and ElGamal keys, which Linus' does not have.'''
        rawdata = load_data('dan.gpg')
        data = BinaryData(rawdata)
        packets = list(data.packets())
        self.assertEqual(9, len(packets))
        # 3 user ID packets
        self.assertEqual(3, sum(1 for p in packets if p.raw == 13))
        # 4 signature packets
        self.assertEqual(4, sum(1 for p in packets if p.raw == 2))

        seen = 0
        for packet in packets:
            self.assertFalse(packet.new)

            if isinstance(packet, PublicSubkeyPacket):
                seen += 1
                self.assertEqual(16, packet.raw_pub_algorithm)
                self.assertEqual("elgamal", packet.pub_algorithm_type)
                self.assertIsNotNone(packet.prime)
                self.assertIsNone(packet.group_order)
                self.assertIsNotNone(packet.group_gen)
                self.assertIsNotNone(packet.key_value)
                self.assertEqual(b"C3751D38", packet.fingerprint[32:])

            elif isinstance(packet, PublicKeyPacket):
                seen += 1
                self.assertEqual(17, packet.raw_pub_algorithm)
                self.assertEqual("dsa", packet.pub_algorithm_type)
                self.assertIsNotNone(packet.prime)
                self.assertIsNotNone(packet.group_order)
                self.assertIsNotNone(packet.group_gen)
                self.assertIsNotNone(packet.key_value)
                self.assertEqual(b"A5CA9D5515DC2CA73DF748CA5C2E46A0F53A76ED",
                        packet.fingerprint)

        self.assertEqual(2, seen)

    def test_parse_junio(self):
        '''This key has a single user attribute packet, which also uses the new
        size format on the outer packet, which is rare.'''
        rawdata = load_data('junio.gpg')
        data = BinaryData(rawdata)
        packets = list(data.packets())
        self.assertEqual(13, len(packets))
        # 3 user ID packets
        self.assertEqual(4, sum(1 for p in packets if p.raw == 13))
        # 4 signature packets
        self.assertEqual(6, sum(1 for p in packets if p.raw == 2))
        # 1 public subkey packet
        self.assertEqual(1, sum(1 for p in packets if p.raw == 14))
        # 1 user attribute packet
        self.assertEqual(1, sum(1 for p in packets if p.raw == 17))

        # check the user attribute packet
        ua_packet = [p for p in packets if p.raw == 17][0]
        self.assertEqual("jpeg", ua_packet.image_format)
        self.assertEqual(1513, len(ua_packet.image_data))


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
            ((2, 1037), bytearray(b'\xb9\x04\x0d')),
            ((2, 5119), [0xb9, 0x13, 0xff]),
            ((4, 100000), [0xba, 0x00, 0x01, 0x86, 0xa0]),
        ]
        for expected, invals in data:
            self.assertEqual(expected, old_tag_length(invals, 0))

    def test_new_tag_length(self):
        data = [
            ((0, 2, False), [0x02]),
            ((0, 16, False), [0x10]),
            ((0, 100, False), [0x64]),
            ((0, 166, False), [0xa6]),
            ((0, 168, False), [0xa8]),
            ((1, 1723, False), [0xc5, 0xfb]),
            ((1, 3923, False), [0xce, 0x93]),
            ((1, 5119, False), [0xd3, 0x3f]),
            ((1, 6476, False), [0xd8, 0x8c]),
            ((0, 8192, True), [0xed]),
            ((4, 26306, False), [0xff, 0x00, 0x00, 0x66, 0xc2]),
            ((4, 26306, False), bytearray(b'\xff\x00\x00\x66\xc2')),
            ((4, 100000, False), [0xff, 0x00, 0x01, 0x86, 0xa0]),
        ]
        for expected, invals in data:
            self.assertEqual(expected, new_tag_length(invals, 0))
