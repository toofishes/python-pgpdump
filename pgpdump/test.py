import base64
from unittest import TestCase

from pgpdump import BinaryData
from pgpdump.packet import TAG_TYPES

class ParseTestCase(TestCase):
    def test_parse_exception(self):
        with self.assertRaises(Exception):
            BinaryData(None)

    def test_parse_single_sig_packet(self):
        base64_sig = "iEYEABECAAYFAk6A4a4ACgkQXC5GoPU6du1ATACgodGyQne3Rb7"\
                "/eHBMRdau1KNSgZYAoLXRWt2G2wfp7haTBjJDFXMGsIMi"
        sig = base64.b64decode(base64_sig)
        data = BinaryData(sig)
        packets = list(data.packets())
        self.assertEqual(1, len(packets))
        sig_packet = packets[0]
        self.assertEqual(1317069230, sig_packet.creation_time)
        self.assertEqual(0x5c2e46a0f53a76ed, sig_packet.key_id)

class PacketTestCase(TestCase):
    def test_lookup_type(self):
        self.assertEqual("Signature Packet", TAG_TYPES[2][0])
