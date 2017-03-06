import textwrap
import frida
import os
import sys
import frida.core
import dumper
import utils
import argparse
import logging
from frida.application import Reactor
import threading
import unicodedata
import re
from itertools import chain

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
    parser.add_argument('--hook', type=str, action='append', help='ApiResolver statements specifying hooks where dumps will be performed')
    parser.add_argument('-n', '--count', type=int, help='maximum number of dumps to take.', default=1)
    args = parser.parse_args()
    return args


print(logo)
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
    print("Can't connect to App. Have you connected the device?")
    sys.exit(0)


# Selecting Output directory
if arguments.out is not None:
    DIRECTORY = arguments.out
    if os.path.isdir(DIRECTORY):
        print(("Output directory is set to: " + DIRECTORY))
    else:
        print("The selected output directory does not exist!")
        sys.exit(1)

else:
    print(("Current Directory: " + str(os.getcwd())))
    DIRECTORY = os.path.join(os.getcwd(), "dump")
    print(("Output directory is set to: " + DIRECTORY))
    if not os.path.exists(DIRECTORY):
        print("Creating directory...")
        os.makedirs(DIRECTORY)

def safe_filename(value):
    import unicodedata
    value = unicodedata.normalize('NFKD', value)
    value = re.sub('[^\w\s-]', '', value).strip().lower()
    value = re.sub('[-\s]+', '-', value)
    return value

mem_access_viol = ""

done = threading.Event()
reactor = Reactor(lambda reactor: done.wait())

dump_count = 0

def do_dump(trigger_name):
    global MAX_SIZE
    global mem_access_viol
    global dump_count

    print("Starting Memory dump...")
    Memories = session.enumerate_ranges(PERMS)

    if arguments.max_size is not None:
        MAX_SIZE = arguments.max_size

    i = 0
    l = len(Memories)

    trigger_name = trigger_name.decode('utf-8')
    dump_count = dump_count + 1
    dump_dir = os.path.join(DIRECTORY, safe_filename("%d-%s" % (dump_count, trigger_name)))

    if arguments.count == 1:
        dump_dir = DIRECTORY

    if not os.path.exists(dump_dir):
        print("Creating directory %s..." % dump_dir)
        os.makedirs(dump_dir)

    # Performing the memory dump
    for memory in Memories:
        base = memory.base_address
        logging.debug("Base Address: " + str(hex(base)))
        logging.debug("")
        size = memory.size
        logging.debug("Size: " + str(size))
        if size > MAX_SIZE:
            logging.debug("Too big, splitting the dump into chunks")
            mem_access_viol = dumper.splitter(session, base, size, MAX_SIZE, mem_access_viol, dump_dir)
            continue
        mem_access_viol = dumper.dump_to_file(session, base, size, mem_access_viol, dump_dir)
        i += 1
        utils.printProgress(i, l, prefix='Progress:', suffix='Complete', bar=50)
    print()

    # Run Strings if selected

    if STRINGS:
        files = os.listdir(dump_dir)
        i = 0
        l = len(files)
        print("Running strings on all files:")
        for f1 in files:
            utils.strings(f1, dump_dir)
            i += 1
            utils.printProgress(i, l, prefix='Progress:', suffix='Complete', bar=50)

    if dump_count >= arguments.count:
        reactor.stop()
        done.set()
        print("Finished!")

jscode = """
var donotpassgo = function() {
    var waiting = true;
    var op = recv('go', function(dummy) {});
    op.wait();
}

function unicodeStringToTypedArray(str) {
    var binary_str = encodeURIComponent(str).replace(/%([0-9A-F]{2})/g, function(match, p1) {
        return String.fromCharCode('0x' + p1);
    });
    var buf = new Uint8Array(binary_str.length);
    for (var i=0, strLen=binary_str.length; i<strLen; i++) {
        buf[i] = binary_str.charCodeAt(i);
    }
    return buf;
}

var stop_hostdump = function(name) {
    send('req_host_dump', unicodeStringToTypedArray(name) );
    donotpassgo();
}

var resolver = new ApiResolver('module');


var hookit = function(tp_pair) {
    target = tp_pair.payload;
    found = false;
    var resolved = {};

    resolver.enumerateMatches(target, {
        onMatch: function(match) {
            if (match.address.toString() in resolved) return;

            console.log("hooking " + match.name + " for dumps")
            try {
                resolved[match.address.toString()] = Interceptor.attach(match.address, {
                    onEnter: function(args) {
                        stop_hostdump(match.name);
                    }
                });
                found = true;
            } catch (e) {
                console.log("Skipping " + match.name + "@" + match.address + ": " + e.message);
            }
        },
        onComplete: function() {
            if (!found) console.log("no match found: " + target);
        }
    });

    recv('ahook', hookit);
}

recv('ahook', hookit);

/* loopback message to initiate dump */
recv('adump', function(tp_pair) {
    stop_hostdump('manual'); //causes hang in session.enumerate_ranges(...) above
})
"""

script = session.create_script(jscode)
def process_message(message, data):
    if message.get('type') != 'send':
        print(message)
        exit(0)

    if message.get('payload') == 'req_host_dump':
        do_dump(data)
        script.post({ 'type': 'go'})

def on_message(message, data):
    reactor.schedule(lambda: process_message(message, data))

script.on('message', on_message)
script.load()

def initiate_dump():
    #initiate a dump
    script.post({ 'type': 'adump' })

if not arguments.hook is None:
    for hook in arguments.hook:
        script.post({ 'type': 'ahook', 'payload': hook })
else:
    if arguments.count > 1:
        print("WARNING: ignoring --count=%d, only one capture supported when there are no --hooks" % arguments.count)
        arguments.count = 1
    reactor.schedule(initiate_dump);

reactor.run()

session.detach()
sys.exit(0)
