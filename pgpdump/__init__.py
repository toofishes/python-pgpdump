from base64 import b64decode

from .packet import construct_packet

BINARY_TAG_FLAG = 0x80

class BinaryData(object):
    def __init__(self, data):
        if not data:
            raise Exception("no data to parse")
        if len(data) <= 1:
            raise Exception("data too short")

        # convert any bytes/str instance to a list of ints
        if isinstance(data, bytes):
            data = [ord(c) for c in data]

        # 7th bit of the first byte must be a 1
        if not bool(data[0] & BINARY_TAG_FLAG):
            raise Exception("incorrect binary data")
        self.data = data
        self.length = len(data)
        self.offset = 0

    def packets(self):
        while self.offset < len(self.data):
            total_length, packet = construct_packet(self.data[self.offset:])
            # increment our data pointer
            self.offset += total_length
            yield packet

    def reset(self):
        self.offset = 0

    def __repr__(self):
        return "<%s: length %d, offset %d>" % (
                self.__class__.__name__, self.length, self.offset)

class AsciiData(BinaryData):
    def __init__(self, data, strip_magic=True):
        self.original_data = data
        if strip_magic:
            data = self.strip_magic(data)
        data = b64decode(data)
        data = [ord(c) for c in data]
        super(AsciiData, self).__init__(data)

    @staticmethod
    def strip_magic(data):
        '''Strip away the '-----BEGIN PGP SIGNATURE-----' and related cruft so
        we can safely base64 decode the remainder.'''
        magic = '-----BEGIN PGP '
        ignore = '-----BEGIN PGP SIGNED '

        # find our magic string
        idx = data.find(magic)
        if idx >= 0:
            # find the start of the actual data. it always immediately follows
            # a blank line, meaning headers are done.
            nl_idx = data.find('\n\n', idx)
            if nl_idx < 0:
                nl_idx = data.find('\r\n\r\n', idx)
            if nl_idx < 0:
                raise Exception("found magic, could not find start of data")
            # now find the end of the data.
            end_idx = data.find('-----', nl_idx)
            if end_idx:
                data = data[nl_idx:end_idx]
            else:
                data = data[nl_idx:]
        return data

    @staticmethod
    def crc24(data):
        # CRC-24-Radix-64
        # x24 + x23 + x18 + x17 + x14 + x11 + x10 + x7 + x6
        #   + x5 + x4 + x3 + x + 1 (OpenPGP)
        # 0x864CFB / 0xDF3261 / 0xC3267D
        crc = 0x00b704ce
        for byte in data:
            crc ^= (byte << 16)
            # optimization: don't have to call range(8) here
            for i in (0, 1, 2, 3, 4, 5, 6, 7):
                crc <<= 1
                if crc & 0x01000000:
                    crc ^= 0x00864cfb
            crc &= 0x00ffffff
        return crc
