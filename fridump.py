import textwrap
import frida
import os
import sys
import frida.core
import dumper
import utils
import argparse
import logging

logo = """
        ______    _     _
        |  ___|  (_)   | |
        | |_ _ __ _  __| |_   _ _ __ ___  _ __
        |  _| '__| |/ _` | | | | '_ ` _ \| '_ \\
        | | | |  | | (_| | |_| | | | | | | |_) |
        \_| |_|  |_|\__,_|\__,_|_| |_| |_| .__/
                                         | |
                                         |_|
        """


# Main Menu
def MENU():
    parser = argparse.ArgumentParser(
        prog='fridump',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(""))

    parser.add_argument('process', help='the process that you will be injecting to')
    parser.add_argument('-o', '--out', type=str, help='provide full output directory path. (def: \'dump\')',
                        metavar="dir")
    parser.add_argument('-u', '--usb', action='store_true', help='device connected over usb')
    parser.add_argument('-v', '--verbose', action='store_true', help='verbose')
    parser.add_argument('-r','--read-only',action='store_true', help="dump read-only parts of memory. More data, more errors")
    parser.add_argument('-s', '--strings', action='store_true',
                        help='run strings on all dump files. Saved in output dir.')
    parser.add_argument('--max-size', type=int, help='maximum size of dump file in bytes (def: 20971520)',
                        metavar="bytes")
    args = parser.parse_args()
    return args


print logo
arguments = MENU()

# Define Configurations
APP_NAME = arguments.process
DIRECTORY = ""
USB = arguments.usb
DEBUG_LEVEL = logging.INFO
STRINGS = arguments.strings
MAX_SIZE = 20971520
PERMS = 'rw-'

if arguments.read_only:
    PERMS = 'r--'

if arguments.verbose:
    DEBUG_LEVEL = logging.DEBUG
logging.basicConfig(format='%(levelname)s:%(message)s', level=DEBUG_LEVEL)

# Start a new Session
session = None
try:
    if USB:
        session = frida.get_usb_device().attach(APP_NAME)
    else:
        session = frida.attach(APP_NAME)
except:
    print "Can't connect to App. Have you connected the device?"
    sys.exit(0)


# Selecting Output directory
if arguments.out is not None:
    DIRECTORY = arguments.out
    if os.path.isdir(DIRECTORY):
        print "Output directory is set to: " + DIRECTORY
    else:
        print "The selected output directory does not exist!"
        sys.exit(1)

else:
    print "Current Directory: " + str(os.getcwd())
    DIRECTORY = os.path.join(os.getcwd(), "dump")
    print "Output directory is set to: " + DIRECTORY
    if not os.path.exists(DIRECTORY):
        print "Creating directory..."
        os.makedirs(DIRECTORY)

mem_access_viol = ""

print "Starting Memory dump..."

Memories = session.enumerate_ranges(PERMS)

if arguments.max_size is not None:
    MAX_SIZE = arguments.max_size

i = 0
l = len(Memories)

# Performing the memory dump
for memory in Memories:
    base = memory.base_address
    logging.debug("Base Address: " + str(hex(base)))
    logging.debug("")
    size = memory.size
    logging.debug("Size: " + str(size))
    if size > MAX_SIZE:
        logging.debug("Too big, splitting the dump into chunks")
        mem_access_viol = dumper.splitter(session, base, size, MAX_SIZE, mem_access_viol, DIRECTORY)
        continue
    mem_access_viol = dumper.dump_to_file(session, base, size, mem_access_viol, DIRECTORY)
    i += 1
    utils.printProgress(i, l, prefix='Progress:', suffix='Complete', bar=50)
print

# Run Strings if selected

if STRINGS:
    files = os.listdir(DIRECTORY)
    i = 0
    l = len(files)
    print "Running strings on all files:"
    for f1 in files:
        utils.strings(f1, DIRECTORY)
        i += 1
        utils.printProgress(i, l, prefix='Progress:', suffix='Complete', bar=50)
print "Finished!"
raw_input('Press Enter to exit...')
