#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
import os
import re
import sys
import argparse
import textwrap
import logging
import frida.core


def dump_to_file(session, base, size, error, directory):
    """Reading bytes from session and saving it to a file """
    try:
            filename = str(hex(base))+'_dump.data'
            dump = session.read_bytes(base, size)
            f = open(os.path.join(directory,filename), 'wb')
            f.write(dump)
            f.close()
            return error
    except:
           print("Oops, memory access violation!")
           return error


def splitter(session, base, size, max_size, error, directory):
    """Read bytes that are bigger than the max_size value, split them into chunks and save them to a file"""
    times = size/max_size
    diff = size % max_size
    if diff is 0:
        logging.debug("Number of chunks:"+str(times+1))
    else:
        logging.debug("Number of chunks:"+str(times))
    global cur_base
    cur_base = base

    for time in range(times):
            logging.debug("Save bytes: "+str(hex(cur_base))+" till "+str(hex(cur_base+max_size)))
            dump_to_file(session, cur_base, max_size, error, directory)
            cur_base = cur_base + max_size

    if diff is not 0:
        logging.debug("Save bytes: "+str(hex(cur_base))+" till "+str(hex(cur_base+diff)))
        dump_to_file(session, cur_base, diff, error, directory)


def printProgress (times, total, prefix='', suffix='', decimals=2, bar=100):
    """Progress bar function"""
    filled = int(round(bar * times / float(total)))
    percents = round(100.00 * (times / float(total)), decimals)
    bar = '#' * filled + '-' * (bar - filled)
    sys.stdout.write('%s [%s] %s%s %s\r' % (prefix, bar, percents, '%', suffix)),
    sys.stdout.flush()
    if times == total:
        print("\n")


def strings(filename, directory, min=4):
    """A very basic implementations of Strings"""
    strings_file = os.path.join(directory, "strings.txt")
    path = os.path.join(directory,filename)

    str_list = re.findall("[A-Za-z0-9/\-:;.,_$%'!()[\]<> \#]+",open(path,"rb").read())
    with open(strings_file,"ab") as st:
        for string in str_list:
            if len(string)>min:
                logging.debug(string)
                st.write(string+b"\n")


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


def main():
    print(logo)
    parser = argparse.ArgumentParser(
        prog='fridump',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(""))

    parser.add_argument('process', help='the process that you will be injecting to')
    parser.add_argument('-o', '--out', type=str, default=os.path.join(os.getcwd(), "dump"),
                        help='provide full output directory path. (def: \'dump\')',
                        metavar="dir")
    parser.add_argument('-u', '--usb', action='store_true', help='device connected over usb')
    parser.add_argument('-v', '--verbose', action='store_true', help='verbose')
    parser.add_argument('-r', '--read-only', action='store_true',
                        help="dump read-only parts of memory. More data, more errors")
    parser.add_argument('-s', '--strings', action='store_true',
                        help='run strings on all dump files. Saved in output dir.')
    parser.add_argument('--max-size', type=int, help='maximum size of dump file in bytes (def: 20971520)',
                        metavar="bytes", default=20971520)
    args = parser.parse_args()

    # Define Configurations
    PERMS = 'r--' if args.read_only else 'rw-'
    LEVEL = logging.DEBUG if args.verbose else logging.INFO

    logging.basicConfig(format='%(levelname)s:%(message)s', level=LEVEL)

    # Start a new Session
    try:
        session = frida.get_usb_device().attach(args.process) if args.usb else frida.attach(args.process)
    except:
        print("Can't connect to App. Have you connected the device?")
        sys.exit(0)

    # Selecting Output directory
    print("Current Directory: " + str(os.getcwd()))
    print("Output directory is set to: " + args.out)
    if os.path.isdir(args.out):
        if not os.path.exists(args.out):
            print("Creating directory...")
            os.makedirs(args.out)

    mem_access_viol = ""

    print("Starting Memory dump...")
    Memories = session.enumerate_ranges(PERMS)

    i, l = 0, len(Memories)
    # Performing the memory dump
    for memory in Memories:
        base = memory.base_address
        logging.debug("Base Address: " + str(hex(base)))
        logging.debug("")
        size = memory.size
        logging.debug("Size: " + str(size))
        if size > args.max_size:
            logging.debug("Too big, splitting the dump into chunks")
            mem_access_viol = splitter(session, base, size, args.max_size, mem_access_viol, args.out)
            continue

        mem_access_viol = dump_to_file(session, base, size, mem_access_viol, args.out)
        i += 1
        printProgress(i, l, prefix='Progress:', suffix='Complete', bar=50)
    print()

    # Run Strings if selected
    if args.string:
        files = os.listdir(args.out)
        i = 0
        l = len(files)
        print("Running strings on all files:")
        for f1 in files:
            strings(f1, args.out)
            i += 1
            printProgress(i, l, prefix='Progress:', suffix='Complete', bar=50)

    print("Finished!")
    return 0


if __name__ == '__main__':
    sys.exit(main())
