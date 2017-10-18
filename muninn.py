#!/usr/bin/env python

__name__ = "Muninn"
__authors__ = ["Yuval tisf Nativ", "Omree Benari"]
__version__ = 0.3
__version_name__ = "charlie"
__license__ = "GPLv3"

import sys
import time
import string
import optparse
import imports.error_handler
import imports.vol_handler
import imports.report_manager


# Muninn - An Automatic Initial Memory Forensics Tool
# Copyright (C) 2014 Yuval tisf Nativ
#``
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


class bcolors:
	HEADER = '\033[95m'
	OKBLUE = '\033[94m'
	OKGREEN = '\033[92m'
	WARNING = '\033[93m'
	FAIL = '\033[91m'
	ENDC = '\033[0m'


def banner():
	a = bcolors.WARNING + "\n _____         _\n"
	a+= "|     |_ _ ___|_|___ ___\n"
	a+= "| | | | | |   | |   |   |\n"
	a+= "|_|_|_|___|_|_|_|_|_|_|_|\n" + bcolors.ENDC
	a+= bcolors.OKGREEN + "  the lazy way to analyze memory images \n\n" + bcolors.ENDC
	a+= "Muninn will take a memory image and a case number.\n"
	a+= "It will then output a text file with basic information\n"
	a+= "it extracted on the machine via the image via volatility.\n"
	a+= "Type " + sys.argv[0] + " -h to get help.\n"
	print a

def print_license():
	print bcolors.WARNING + "\n######################################################################"
	print bcolors.OKGREEN + "                              GPLv3" + bcolors.WARNING
	print "######################################################################" + bcolors.ENDC
	print "Muninn - An Automatic Initial Memory Forensics Tool"
	print "Copyright (C) 2014 Yuval tisf Nativ"
	print ""
	print "This program is free software: you can redistribute it and/or modify"
	print "it under the terms of the GNU General Public License as published by"
	print "the Free Software Foundation, either version 3 of the License, or"
	print "(at your option) any later version."
	print ""
	print "This program is distributed in the hope that it will be useful,"
	print "but WITHOUT ANY WARRANTY; without even the implied warranty of"
	print "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the"
	print "GNU General Public License for more details."
	print ""
	print "You should have received a copy of the GNU General Public License"
	print "along with this program.  If not, see <http://www.gnu.org/licenses/>."
	print ""


''' Get basic handlers '''
vol = imports.vol_handler.VolatiltyHandler()										# Volatility Handler
doc = imports.report_manager.Secretary()											# Doc Manager
shit = imports.error_handler.Shit_Handler()											# I give you; Shit!
vol.check_if_vol_is_installed()														# Read the label

''' Argument Parsing is done here '''
parser = optparse.OptionParser()
parser.add_option('-f', '--file', dest='filename', help="The path to memory image to analyse")
parser.add_option('-c', '--case', dest='casenumber', help="Case number to use")
parser.add_option('-v', '--version', action="store_true", dest="ver_flag", default=False, help="Print version information.")
(options, args) = parser.parse_args()

''' Test for -v flag '''
ver_flag = options.ver_flag
if ver_flag:
	banner()
	print_license()
	sys.exit(0)

if options.filename is None:
	banner()
	sys.exit(0)

if options.casenumber is None:
	banner()
	sys.exit(0)

filename = options.filename
casenumber = options.casenumber


'''
#######################################
     Real program starts here
#######################################
'''
date = time.ctime(time.time())

banner()

shit.error_log(1, "Starting to analyze " + filename + " at " + date)


''' Starting actual work and analysis '''
vol.document_image_details(filename)												# Guess
vol.get_image_type(filename)														# I'm getting tired...
vol.get_process_list()																# Will you read the label?!
vol.hive_list()																		# Getting hives from mem image
vol.find_hashes()																	# Get Local hashes
vol.get_network_connections()														# Get all network connections
vol.get_runkey_from_reg()															# Get startup values
vol.drivers()																		# Get all drivers in memory image


doc.InitiateDocument(casenumber, date, filename, vol._md5sum, vol._image_type)		# Generate document template

''' Print Process List '''
process_array = []
process_header = ['Offset', 'PID', 'Name', 'Parent PID']
for each in vol._all_processes:
	array = [each.offset, each.pid, each.name, each.ppid ]
	process_array.append(array)

doc.print_title("Processes Found (%s)" % len(process_array), 3)
doc.print_table(process_header, process_array, process_header[1])


''' Print Hive List '''
hive_array = []
hive_header = ["Virtual Offset", "Hive Name"]
for each in vol._hives:
	array = [each.vir_offset, each.name]
	hive_array.append(array)

doc.print_title("Hive List (%s)" % len(hive_array), 3)
doc.print_table(hive_header, hive_array, hive_header[1])


''' Print Hashes '''
cred_array = []
cred_header = ["User Name", "UID", "LM", "NTLM"]
for each in vol._creds:
	array = [each.username, each.uid, each.lm, each.ntlm]
	cred_array.append(array)

doc.print_title("Hashes Found (%s)" % len(cred_array), 3)
doc.print_table(cred_header, cred_array, cred_header[1])


''' Startup Keys In Registry '''
startupkeys_array = []
startupkeys_header = ["Name"]
for each in vol._startup_keys:
	a = filter(lambda x: x in string.printable, str(each))
	startupkeys_array.append([a])

doc.print_title("Startup Keys In Registry (%s)" % len(startupkeys_array), 3)
doc.print_table(startupkeys_header, startupkeys_array, startupkeys_header[0])


''' Print TCP Connections '''
tcp_array = []
tcp_header = ["IP Version", "Bind Address", "Bind Port", "Remote Address", "Remote Port", "State",  "PID"]
for each in vol._connections_tcp:
	array = [each.ver, each.bind_add, each.bind_port, each.remote_addr, each.remote_port, each.state, each.pid]
	tcp_array.append(array)

doc.print_title("TCP Connections List (%s)" % len(tcp_array), 3)
doc.print_table(tcp_header, tcp_array, tcp_header[0])


''' Print UDP Connections '''
udp_array = []
udp_header = ["Port Number", "Version", "Bind Address", "PID", "Process Name"]
for each in vol._connections_udp:
	array = [each.bind_port, each.ver, each.bind_add, each.pid, each.p_name]
	udp_array.append(array)

doc.print_title("UDP Connections List (%s)" % len(udp_array), 3)
doc.print_table(udp_header, udp_array, udp_header[0])


''' Print Drivers '''
driver_array = []
driver_header = ["Driver Name", "Short Name", "Offset", "Pointers", "Handlers", "Start", "Size" ]
for each in vol._drivers:
	array = [each.full_name, each.name, each.offset, each.pointers, each.handlers, each.start, each.size]
	driver_array.append(array)

doc.print_title("Drivers (%s)" % len(driver_array), 3)
doc.print_table(driver_header, driver_array, driver_header[0])
