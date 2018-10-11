import textwrap
import frida
import os
import sys
import frida.core
import dumper
import utils
import argparse
import logging



class Fridump:

	def __init__(self, App_Name = None, Directory = None, USB = False, Remote = False, Debug_Level = logging.INFO, Strings = False, Max_Size = 20971520, Perms = 'rw-'):
		self.arguments = None
		self.session = None
		self.parser = None
		self.App_Name = App_Name
		self.Directory = Directory
		self.USB = USB
		self.Remote = Remote
		self.Debug_Level = Debug_Level
		self.Strings = Strings
		self.Max_Size = Max_Size
		self.Perms = Perms
		self.mem_access_viol = ""

	def MENU(self):
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
		
		self.parser = argparse.ArgumentParser(
	        prog='fridump',
	        formatter_class=argparse.RawDescriptionHelpFormatter,
	        description=textwrap.dedent(""))
		self.parser.add_argument('process', 
			help='the process that you will be injecting to')
		self.parser.add_argument('-o', '--out', type=str, metavar="dir", 
			help='provide full output directory path. (def: \'dump\')')
		self.parser.add_argument('-U', '--usb', action='store_true', 
			help='device connected over usb')
		self.parser.add_argument('-R', '--remote', action='store_true',
			help='device connected over network')
		self.parser.add_argument('-v', '--verbose', action='store_true', 
			help='verbose')
		self.parser.add_argument('-r', '--read_only', action='store_true', 
			help="dump read-only parts of memory. More data, more errors")
		self.parser.add_argument('-s', '--strings', action='store_true', 
			help='run strings on all dump files. Saved in output dir.')
		self.parser.add_argument('--max-size', type=int, metavar="bytes", 
			help='maximum size of dump file in bytes (def: 20971520)')
		
		#Used to assing parsed information
		self.arguments = self.parser.parse_args()
		self.USB = self.arguments.usb
		self.Remote = self.arguments.remote
		self.Strings = self.arguments.strings
		self.App_Name = self.arguments.process
		self.Directory = self.arguments.out
		
		if self.arguments.read_only:
			self.Perms = 'r--'
		else:
			self.Perms = 'rw--'	
		self.Debug_Level = self.arguments.verbose

		print(logo)

	def String(self):
		files = os.listdir(self.Directory)
		i = 0
		l = len(files)
		for f1 in files:
		    utils.strings(f1, self.Directory)
		    i += 1
		    utils.printProgress(i, l, prefix='Progress:', suffix='Complete', bar=50)
		print("Finished!")
	
	def Session(self):
		print(self.App_Name)
		try:
			if self.USB:
				self.session = frida.get_usb_device().attach(self.App_Name)
			elif self.Remote:
				self.session = frida.get_remote_device().attach(self.App_Name)
			else:
				self.session = frida.attach(self.App_Name)
		except Exception as e:
			print("Cant connect to application. Have you connected the device?")
			logging.debug(str(e))
			sys.exit()

	def Dir(self):
		
		if self.Directory != None:
			print(self.Directory)	
			if os.path.isdir(self.Directory):
				print("Output directory is set to: ", self.Directory)
			else:
				print("The selected output directory does not exist!")
				sys.exit(1)
		else:
			print("Current directory: ", str(os.getcwd()))
			place = os.path.join(os.getcwd(), "dump")
			self.Directory = place
			if not os.path.exists(place):
				print("Creating directory...")
				os.makedirs(place)
	
	def Script(self):

		print("Starting Memory dump...")
		script = self.session.create_script(
		    """'use strict';

		    rpc.exports = {
		      enumerateRanges: function (prot) {
		        return Process.enumerateRangesSync(prot);
		      },
		      readMemory: function (address, size) {
		        return Memory.readByteArray(ptr(address), size);
		      }
		    };

		    """)
		script.on("message", utils.on_message)
		script.load()

		agent = script.exports
		print(self.Perms)
		ranges = agent.enumerate_ranges(self.Perms)

		if self.Max_Size is not None:
		    MAX_SIZE = self.Max_Size

		i = 0
		l = len(ranges)

		# Performing the memory dump
		for range in ranges:
		    base = range["base"]
		    size = range["size"]

		    logging.debug("Base Address: " + str(base))
		    logging.debug("")
		    logging.debug("Size: " + str(size))

		    if size > MAX_SIZE:
		        logging.debug("Too big, splitting the dump into chunks")
		        self.mem_access_viol = dumper.splitter(
		            agent, base, size, MAX_SIZE, self.mem_access_viol, self.Directory)
		        continue
		    self.mem_access_viol = dumper.dump_to_file(
		        agent, base, size, self.mem_access_viol, self.Directory)
		    i += 1
		    utils.printProgress(i, l, prefix='Progress:', suffix='Complete', bar=50)
		print("")

		if self.Strings:
			self.String()

testobj = Fridump( )
testobj.MENU()
testobj.Session()
testobj.Dir()
testobj.Script()
