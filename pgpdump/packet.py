import binascii
import math

from datetime import datetime

NEW_TAG_FLAG    = 0x40
TAG_MASK        = 0x3f
PARTIAL_MASK    = 0x1f

OLD_LEN_MASK    = 0x03
OLD_TAG_SHIFT   = 2
TAG_COMPRESSED  = 8

CRITICAL_BIT    = 0x80
CRITICAL_MASK   = 0x7f

def _getint(data, offset, nbytes):
    """Gets nbytes bytes from data at offset and return as an integer"""
    return int(binascii.hexlify(
                data[offset:offset+nbytes]),
               16)

def _get_mpi(data, offset):
    """Gets a multi-precision integer as per rfc-4880
    Returns the MPI, in hexlified form, and the new offset.
    See: http://tools.ietf.org/html/rfc4880#section-3.2"""
    mpi_len = _getint(data, offset, 2)
    _len = int(math.ceil(mpi_len/8.))
    mpi_bytestream = data[offset+2:offset+2+_len]
    mpi = binascii.hexlify(mpi_bytestream)
    offset += (2 + _len)
    return mpi, offset


class Packet(object):
    '''The base packet object containing various fields pulled from the packet
    header as well as a slice of the packet data.'''
    def __init__(self, raw, name, new, partial, data):
        self.raw = raw
        self.name = name
        self.new = new
        self.partial = partial
        self.length = len(data)
        self.data = data

        # now let subclasses work their magic
        self.parse()

    def parse(self):
        '''Perform any parsing necessary to populate fields on this packet.
        This method is called as the last step in __init__(). The base class
        method is a no-op; subclasses should use this as required.'''
        pass

    def __repr__(self):
        new = "old"
        if self.new:
            new = "new"
        return "<%s: %s (%d), %s, length %d>" % (
                self.__class__.__name__, self.name, self.raw, new, self.length)


class AlgoLookup(object):
    @staticmethod
    def lookup_pub_algorithm(alg):
        algorithms = {
            1:  "RSA Encrypt or Sign",
            2:  "RSA Encrypt-Only",
            3:  "RSA Sign-Only",
            16: "ElGamal Encrypt-Only",
            17: "DSA Digital Signature Algorithm",
            18: "Elliptic Curve",
            19: "ECDSA",
            20: "Formerly ElGamal Encrypt or Sign",
            21: "Diffie-Hellman",
        }
        return algorithms.get(alg, "Unknown")

    @staticmethod
    def lookup_hash_algorithm(alg):
        reserved_values = (4, 5, 6, 7)
        algorithms = {
            1:  "MD5",
            2:  "SHA1",
            3:  "RIPEMD160",
            8:  "SHA256",
            9:  "SHA384",
            10: "SHA512",
            11: "SHA224",
        }
        if alg in reserved_values:
            return "Reserved"
        return algorithms.get(alg, "Unknown")


class SignatureSubpacket(object):
    '''A signature subpacket containing a type, type name, some flags, and the
    contained data.'''
    def __init__(self, raw, name, hashed, critical, data):
        self.raw = raw
        self.name = name
        self.hashed = hashed
        self.critical = critical
        self.length = len(data)
        self.data = data

    def __repr__(self):
        hashed = ""
        if self.hashed:
            hashed = "hashed, "
        return "<%s: %s (%d), %slength %d>" % (
                self.__class__.__name__, self.name, self.raw,
                hashed, self.length)

class SignaturePacket(Packet, AlgoLookup):
    def __init__(self, *args, **kwargs):
        self.hash_material = None
        self.sig_version = None
        self.raw_sig_type = None
        self.sig_type = None
        self.raw_pub_algorithm = None
        self.pub_algorithm = None
        self.raw_hash_algorithm = None
        self.hash_algorithm = None
        self.creation_time = None
        self.datetime = None
        self.key_id = None
        self.hash2 = None
        self.subpackets = []
        super(SignaturePacket, self).__init__(*args, **kwargs)

    def parse(self):
        self.sig_version = self.data[0]
        offset = 1
        if self.sig_version == 3:
            # 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
            # |  |  [  ctime  ] [ key_id                 ] |
            # |  |-type                           pub_algo-|
            # |-hash material
            # 10 11 12
            # |  [hash2]
            # |-hash_algo

            self.hash_material = self.data[offset]
            offset += 1

            self.raw_sig_type = self.data[offset]
            self.sig_type = self.lookup_signature_type(self.data[offset])
            offset += 1

            ts = _getint(self.data, offset, 4)
            self.creation_time = ts
            self.datetime = datetime.fromtimestamp(ts)
            offset += 4

            self.key_id = _getint(self.data, offset, 8)
            offset += 8

            self.raw_pub_algorithm = self.data[offset]
            self.pub_algorithm = self.lookup_pub_algorithm(self.data[offset])
            offset += 1

            self.raw_hash_algorithm = self.data[offset]
            self.hash_algorithm = self.lookup_hash_algorithm(self.data[offset])
            offset += 1

            self.hash2 = self.data[offset:offset + 2]
            offset += 2

        elif self.sig_version == 4:
            # 00 01 02 03 ... <hashedsubpackets..> <subpackets..> [hash2]
            # |  |  |-hash_algo
            # |  |-pub_algo
            # |-type

            self.raw_sig_type = self.data[offset]
            self.sig_type = self.lookup_signature_type(self.data[offset])
            offset += 1

            self.raw_pub_algorithm = self.data[offset]
            self.pub_algorithm = self.lookup_pub_algorithm(self.data[offset])
            offset += 1

            self.raw_hash_algorithm = self.data[offset]
            self.hash_algorithm = self.lookup_hash_algorithm(self.data[offset])
            offset += 1

            # next is hashed subpackets
            length = _getint(self.data, offset, 2)
            offset += 2
            self.parse_subpackets(offset, length, True)
            offset += length

            # followed by subpackets
            length = _getint(self.data, offset, 2)
            offset += 2
            self.parse_subpackets(offset, length, False)
            offset += length

            self.hash2 = self.data[offset:offset + 2]
            offset += 2

    def parse_subpackets(self, outer_offset, outer_length, hashed=False):
        offset = outer_offset
        while offset < outer_offset + outer_length:
            # each subpacket is [variable length] [subtype] [data]
            sub_offset, sub_length = new_tag_length(self.data[offset:])
            # sub_length includes the subtype single byte, knock that off
            sub_length -= 1
            # initial length bytes
            offset += 1 + sub_offset

            subtype = self.data[offset]
            offset += 1

            critical = bool(subtype & CRITICAL_BIT)
            subtype &= CRITICAL_MASK
            name = self.lookup_signature_subtype(subtype)

            sub_data = self.data[offset:offset + sub_length]
            subpacket = SignatureSubpacket(subtype, name,
                    hashed, critical, sub_data)
            if subpacket.raw == 2:
                ts = _getint(subpacket.data, 0, 4)
                self.creation_time = ts
                self.datetime = datetime.fromtimestamp(ts)
            elif subpacket.raw == 16:
                self.key_id = _getint(subpacket.data, 0, 8)
            offset += sub_length
            self.subpackets.append(subpacket)

    @staticmethod
    def lookup_signature_type(typ):
        sig_types = {
            0x00: "Signature of a binary document",
            0x01: "Signature of a canonical text document",
            0x02: "Standalone signature",
            0x10: "Generic certification of a User ID and Public Key packet",
            0x11: "Persona certification of a User ID and Public Key packet",
            0x12: "Casual certification of a User ID and Public Key packet",
            0x13: "Positive certification of a User ID and Public Key packet",
            0x18: "Subkey Binding Signature",
            0x19: "Primary Key Binding Signature",
            0x1f: "Signature directly on a key",
            0x20: "Key revocation signature",
            0x28: "Subkey revocation signature",
            0x30: "Certification revocation signature",
            0x40: "Timestamp signature",
            0x50: "Third-Party Confirmation signature",
        }
        return sig_types.get(typ, "Unknown")


    @staticmethod
    def lookup_signature_subtype(typ):
        reserved_types = (0, 1, 8, 13, 14, 15, 17, 18, 19)
        subpacket_types = {
            2:  "signature creation time",
            3:  "signature expiration time",
            4:  "exportable certification",
            5:  "trust signature",
            6:  "regular expression",
            7:  "revocable",
            9:  "key expiration time",
            10: "additional decryption key",
            11: "preferred symmetric algorithms",
            12: "revocation key",
            16: "issuer key ID",
            20: "notation data",
            21: "preferred hash algorithms",
            22: "preferred compression algorithms",
            23: "key server preferences",
            24: "preferred key server",
            25: "primary User ID",
            26: "policy URL",
            27: "key flags",
            28: "signer's User ID",
            29: "reason for revocation",
            30: "features",
            31: "signature target",
            32: "embedded signature",
        }
        if typ in reserved_types:
            return "reserved"
        return subpacket_types.get(typ, "unknown")


class PublicKeyPacket(Packet, AlgoLookup):
    def __init__(self, *args, **kwargs):
        self.pubkey_version = None
        self.creation_time = None
        self.datetime = None
        self.mod = None
        self.exp = None
        super(PublicKeyPacket, self).__init__(*args, **kwargs)

    def parse(self):
        self.pubkey_version = self.data[0]
        offset = 1
        if self.pubkey_version == 4:
            ts = _getint(self.data, offset, 4)
            self.creation_time = ts
            self.datetime = datetime.fromtimestamp(ts)
            offset += 4

            self.raw_pub_algorithm = self.data[offset]
            self.pub_algorithm = self.lookup_pub_algorithm(self.data[offset])
            offset += 1

            #If RSA:
            if self.raw_pub_algorithm == 1:
                self.mod, offset = _get_mpi(self.data, offset)
                self.exp, offset = _get_mpi(self.data, offset)
                self.exp_int = int(self.exp, 16)


TAG_TYPES = {
    # (Name, PacketType) tuples
    0:  ("Reserved", None),
    1:  ("Public-Key Encrypted Session Key Packet", None),
    2:  ("Signature Packet", SignaturePacket),
    3:  ("Symmetric-Key Encrypted Session Key Packet", None),
    4:  ("One-Pass Signature Packet", None),
    5:  ("Secret Key Packet", None),
    6:  ("Public Key Packet", PublicKeyPacket),
    7:  ("Secret Subkey Packet", None),
    8:  ("Compressed Data Packet", None),
    9:  ("Symmetrically Encrypted Data Packet", None),
    10: ("Marker Packet", None),
    11: ("Literal Data Packet", None),
    12: ("Trust Packet", None),
    13: ("User ID Packet", None),
    14: ("Public Subkey Packet", None),
    17: ("User Attribute Packet", None),
    18: ("Symmetrically Encrypted and MDC Packet", None),
    19: ("Modification Detection Code Packet", None),
    60: ("Private", None),
    61: ("Private", None),
    62: ("Private", None),
    63: ("Private", None),
}

def new_tag_length(data):
    '''takes the data as a list of int/longs as input;
    returns (offset, length).'''
    first = data[0]
    offset = length = 0

    if first < 192:
        length = first
    elif first < 224:
        offset = 1
        length = ((first - 192) << 8) + data[1] + 192
    elif first == 255:
        offset = 4
        length = _getint(data, 1, 4)
    else:
        length = 1 << (first & PARTIAL_MASK)

    return (offset, length)

def old_tag_length(data, tag):
    '''takes the data as a list of int/longs as input;
    also the shifted old tag. Returns (offset, length).'''
    offset = length = 0
    temp_len = data[0] & OLD_LEN_MASK

    if temp_len == 0:
        offset = 1
        length = data[1]
    elif temp_len == 1:
        offset = 2
        length = _getint(data, 1, 2)
    elif temp_len == 2:
        offset = 4
        length = _getint(data, 1, 4)
    elif temp_len == 3:
        if tag == TAG_COMPRESSED:
            length = 0
        else:
            length = -1

    return (offset, length)

def construct_packet(data):
    tag = data[0] & TAG_MASK
    new = bool(data[0] & NEW_TAG_FLAG)
    if new:
        offset, length = new_tag_length(data[1:])
        offset += 1
        partial = (data[0] >= 224 or data[0] < 255)
    else:
        tag >>= OLD_TAG_SHIFT
        offset, length = old_tag_length(data, tag)
        if length == -1:
            length = len(data) - offset
        partial = False
    offset += 1
    name, PacketType = TAG_TYPES.get(tag, ("Unknown", None))
    packet_data = data[offset:offset + length]
    total_length = offset + length
    if not PacketType:
        PacketType = Packet
    packet = PacketType(tag, name, new, partial, packet_data)
    return (total_length, packet)

