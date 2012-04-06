import sys

from . import AsciiData, BinaryData


def parsefile(name):
    with open(name, 'rb') as infile:
        if name.endswith('.asc'):
            data = AsciiData(infile.read())
        else:
            data = BinaryData(infile.read())
    counter = length = 0
    for packet in data.packets():
        counter += 1
        length += packet.length
    print('%d packets, length %d' % (counter, length))


def main():
    for filename in sys.argv[1:]:
        parsefile(filename)


if __name__ == '__main__':
    #import cProfile
    #cProfile.run('main()', 'pgpdump.profile')
    main()
