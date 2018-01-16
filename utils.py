import os
import re
import sys

from io import open
from mmap import mmap, PROT_READ

if '__enter__' not in mmap.__dict__:
    class mmap(mmap):
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            self.close()

# Progress bar function
def printProgress(times, total, prefix='', suffix='', decimals=2, bar=100):
    filled = int(round(bar * times / float(total)))
    percents = round(100.00 * (times / float(total)), decimals)
    bar = '#' * filled + '-' * (bar - filled)
    sys.stdout.write('%s [%s] %s%s %s\r' % (prefix, bar, percents, '%', suffix)),
    sys.stdout.flush()
    if times == total:
        print("\n")


# A very basic implementations of Strings
def strings(filename, directory, min=6):
    path = os.path.join(directory, filename)

    with open(path, 'rb') as f, mmap(f.fileno(), 0, access=PROT_READ) as m:

        for match in re.finditer(('([\w/]{{{}}}[\w/]*)'.format(min)).encode(), m):
            yield match.group(0).decode("utf-8")


def find_dump_strings(directory):
    files = os.listdir(directory)
    strings_file = os.path.join(directory, "strings.txt")

    l = len(files) - 1
    print("Running strings on all files:")
    with open(strings_file, "wb") as st:
        for idx, f1 in enumerate(files):
            if f1.endswith("_dump.data"):
                st.write("\n".join(strings(f1, directory)).encode())
                printProgress(idx, l, prefix='Progress:', suffix='Complete', bar=50)
