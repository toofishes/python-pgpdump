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

class AsciiData(object):
    pass
