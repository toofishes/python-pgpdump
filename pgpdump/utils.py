def crc24(data):
    '''Implementation of the OpenPGP CRC-24 algorithm.'''
    # CRC-24-Radix-64
    # x24 + x23 + x18 + x17 + x14 + x11 + x10 + x7 + x6
    #   + x5 + x4 + x3 + x + 1 (OpenPGP)
    # 0x864CFB / 0xDF3261 / 0xC3267D
    crc = 0x00b704ce
    for byte in data:
        crc ^= (byte << 16)
        # optimization: don't have to call range(8) here
        for _ in (0, 1, 2, 3, 4, 5, 6, 7):
            crc <<= 1
            if crc & 0x01000000:
                crc ^= 0x00864cfb
        crc &= 0x00ffffff
    return crc
