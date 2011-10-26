import sys
import cProfile

from . import AsciiData, BinaryData

def parsefile(name):
    with open(name) as infile:
        if name.endswith('.asc'):
            data = AsciiData(infile.read())
        else:
            data = BinaryData(infile.read())
    counter = 0
    for packet in data.packets():
        counter += 1
    print(counter)

def main():
    for filename in sys.argv[1:]:
        parsefile(filename)

if __name__ == '__main__':
    cProfile.run('main()', 'main.profile')
