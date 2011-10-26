import sys

from . import BinaryData

for filename in sys.argv[1:]:
    with open(filename) as infile:
        data = BinaryData(infile.read())
        for packet in data.packets():
            print hex(packet.key_id), packet.creation_date
