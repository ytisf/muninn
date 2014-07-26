#!/usr/bin/env python

import os
import re
import hashlib
import commands

import imports.error_handler


class VolatiltyHandler():
	'''
	This class will run volatility with particular arguments and will
	manage the output from it.
	'''
	def __init__(self):
		self._volatility_handler = ""
		self._shit_handler = imports.error_handler.Shit_Handler()
		self._is_vol_okay = 0

		# Analysis structure
		self._image_type = ""
		self._image_location = ""
		self._volname = "vol.py"
		self._all_processes = ""
		self._md5sum = ""
		self._imagesize = ""
		self._hives = []
		self._creds = []
		self._connections_udp = []
		self._connections_tcp = []
		self._startup_keys = []
		self._drivers = []


	def regex_search(self, data, regex):
		'''
		This function runs regex search on data given
		and returns output.
		:data the data to run through the filter
		:regex the regex query
		:return the filtered result of the search
		'''
		results = re.search(regex, data)
		return results


	def check_if_vol_is_installed(self):
		'''
		This function checks if volatility exists as vol.py.
		If it does not, it throws a type 4 error to shit_handler and exists
		'''
		status, output = commands.getstatusoutput("vol.py")
		if int(status) == 256:
			self._is_vol_okay = 1
		else:
			self._shit_handler.error_log(5, "Volatility was not found.")


	def get_image_type(self, imagelocation):
		'''
		This function will try to get the image_type of the memory image
		If the imagetype is not successfully extracted an exception will occur.
		The imagetype will be returned to class var self._imagetype

		Other functions depend on this function to create the parent attribute of the file name.

		This function will also match the complete image path in to the class var self._image_location
		:param imagelocation: The file location of the image to be analyzed
		:return: Will return a 1 in case of an error
		'''

		self._shit_handler.error_log(1, "Getting image type")

		self._image_location = str(imagelocation)

		command = self._volname + " -f " + str(imagelocation) + " imageinfo | grep -e \"\s*Sugg\""
		status, output = commands.getstatusoutput(command)
		regi = "[\" : \"](.+)\,"
		status = 0

		if status == 0:
			jibbily = self.regex_search(output, regi)
			jibbily = jibbily.groups()
			jibbily = jibbily[0]
			jibbily = jibbily[32:]
			self._image_type = jibbily
		else:
			self._shit_handler.error_log(4, "Did not detect imagetype.")

		self._shit_handler.error_log(0, "Image recognized as %s" % self._image_type)


	def document_image_details(self, imagelocation):
		'''
		This function will get the MD5 sum of the image along with size and other types of information.
		The other functions are not dependent of it and it can run 'autonomously'.
		:param imagelocation: The file location of the image to be analyzed
		:return: Will return a 1 in case of an error
		'''

		self._shit_handler.error_log(1, "Getting MD5 sum")

		fileHandle = open(imagelocation, "rb")
		m5Hash = hashlib.md5()
		while True:
			data = fileHandle.read(8192)
			if not data:
				break
			m5Hash.update(data)
		fileHandle.close()

		self._imagesize = (os.path.getsize(imagelocation) >> 20)  # size is offseted in 20 to get size in MB
		self._md5sum = m5Hash.hexdigest()
		self._shit_handler.error_log(0, "MD5 sum generated and is: %s" % self._md5sum)


	def get_process_list(self):
		'''
		This function will extract all processes listed in memory image using
		psscan method in vol.py
		'''

		# Function vars
		class vol_proc(object):
			def __init__(self):
				pass

		self._shit_handler.error_log(1, "Getting all processes from file using 'psscan'")

		regi = "([0x].........)\s(.+.exe)\s+(\d+)\s+(\d+)\s+([0x].........)\s+(............................)"
		all_processes = []

		# Execute command
		command = self._volname + " -f " + self._image_location + " --profile=" + self._image_type + " psscan"
		status, output = commands.getstatusoutput(command)

		output = output.split('\n')

		# Check if there is any output from command
		if len(output) == 0:
			self._shit_handler.error_log(3, "Finding process command returned 0 results")
			return 1

		for proc in output:
			temp = self.regex_search(proc, regi)
			try:
				temp = temp.groups()
				process = vol_proc()
				process.offset = temp[0]
				process.name = temp[1]
				process.pid = temp[2]
				process.ppid = temp[3]
				process.pdb = temp[4]
				process.timestamp_cr = temp[5]
				all_processes.append(process)

			except:
				# line not matching
				pass
		self._shit_handler.error_log(0, "Got " + str(len(all_processes)) + " processes using 'psscan'")
		self._all_processes = all_processes


	def hive_list(self):
		'''
		This function will extract all hives listed in memory image using
		hivelist method in vol.py
		'''

		class hive(object):
			def __init__(self):
				pass

		self._shit_handler.error_log(1, "Starting hivelist harvesting")

		regi = "(0x........)\s(0x........)\s(.+)"
		hives = []

		command = self._volname + " -f " + self._image_location + " --profile=" + self._image_type + " hivelist"
		status, output = commands.getstatusoutput(command)

		output = output.split('\n')

		if len(output) == 0:
			self._shit_handler.error_log(1, "Finding hivelist returned 0 results")
			return 1

		for hive_i in output:
			temp = self.regex_search(hive_i, regi)
			try:
				temp = temp.groups()
				current_hive = hive()
				current_hive.vir_offset = temp[0]
				current_hive.phy_offset = temp[1]
				current_hive.name = temp[2]
				hives.append(current_hive)

			except:
				# no matches found
				pass

		self._shit_handler.error_log(0, "Got " + str(len(hives)) + " hives using 'hivelist'")
		self._hives = hives


	def find_hashes(self):
		'''
		This function will find hashes in memory. After that it will build an object
		of credentials for each credentials found and turn it into a global object.
		'''

		class hash(object):
			def __init__(self):
				pass

		self._shit_handler.error_log(1, "Starting hash harvesting")

		all_creds = []

		sam_offset = ""
		sys_offset = ""

		regi = "(.+):(\d{3,5}):(.{32}):(.{32})"

		for hive in self._hives:
			i = hive.name.find("SAM")
			if i == -1:
				j = hive.name.find("SYSTEM")
				if j == -1:
					j = hive.name.find("system")
					if j == -1:
						pass
					else:
						sys_offset = hive.vir_offset
				else:
					sys_offset = hive.vir_offset
			else:
				sam_offset = hive.vir_offset

		command = self._volname + " -f " + self._image_location + " --profile=" + self._image_type + " -s " + sam_offset + " -y " + sys_offset + " hashdump"
		status, output = commands.getstatusoutput(command)

		output = output.split('\n')
		output = output[1:]

		if len(output) == 0:
			self._shit_handler.error_log(1, "Found 0 users.")
			return 1

		for creds in output:
			temp = self.regex_search(creds, regi)
			try:
				temp = temp.groups()
				current_creds = hash()
				current_creds.username = temp[0]
				current_creds.uid = temp[1]
				current_creds.lm = temp[2]
				current_creds.ntlm = temp[3]
				all_creds.append(current_creds)

			except:
				# no matches found
				pass

		self._creds = all_creds
		self._shit_handler.error_log(0, "Found %s hashes in memory" % len(all_creds))


	def get_network_connections(self):
		'''
		DO NOT start reading or changing this function!
		There is some black magic regex voodoo here and it's not nice.
		Basically it will give you a list of network connections splitted by TCP
		and by UDP but i don't think you want to go into this...
		'''

		self._shit_handler.error_log(1, "Getting network traffic information'")

		class net_socket(object):
			def __init__(self):
				pass

		tcp_array = []
		udp_array = []

		tcp_regex = "(0x........)\s(TCPv\d)\s+(.+):(\d{1,5})\s+(.+):(\d{1,5})\s+(LISTENING | ESTABLISHED | CLOSED | CLOSE_WAIT)\s+([0-9-]+)\s+(.+)"
		udp_regex = "(0x........)\s(UDPv\d)\s+(.+):(\d{1,5})\s+[*:]{3}\s+([0-9-]+)\s+([a-zA-Z.-]+)\s+([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} UTC[0-9+]+)"

		xp = self._image_type.find("WinXP")
		sev = self._image_type.find("Win7")

		if xp == -1:
			# this is a windows7 machine
			command = self._volname + " -f " + self._image_location + " --profile=" + self._image_type + " netscan"
			self._shit_handler.error_log(1, "Network connections identified machine as Win7'")

		elif sev == -1:
			# This is a windowsXP machine
			command = self._volname + " -f " + self._image_location + " --profile=" + self._image_type + " connscan"
			self._shit_handler.error_log(1, "Network connections identified machine as WinXP'")

		else:
			# Da faq did you just do?!
			self._shit_handler.error_log(3, "Error in finding machine state in vol_handler.get_network_connections'")
			return 1

		status, output = commands.getstatusoutput(command)
		output = output.split('\n')

		if len(output) == 0:
			self._shit_handler.error_log(3, "Fuck this shit. I'ma Duck!")
			return 1

		for connection in output:
			b = connection.find("TCP")
			a = connection.find("UDP")

			if a == 11:
				# This is a UDP Connection
				temp = self.regex_search(connection, udp_regex)
				temp = temp.groups()
				current_conn = net_socket()
				current_conn.offset = temp[0]
				current_conn.ver = temp[1]
				current_conn.bind_add = temp[2]
				current_conn.bind_port = temp[3]
				current_conn.pid = temp[4]
				current_conn.p_name = temp[5]
				current_conn.time = temp[6]
				udp_array.append(current_conn)

			elif b == 11:
				# This is a TCP Connection
				try:
					temp = self.regex_search(connection, tcp_regex)
					temp = temp.groups()
					current_conn = net_socket()
					current_conn.offset = temp[0]
					current_conn.ver = temp[1]
					current_conn.bind_add = temp[2]
					current_conn.bind_port = temp[3]
					current_conn.remote_addr = temp[4]
					current_conn.remote_port = temp[5]
					current_conn.state = temp[6]
					current_conn.pid = temp[7]
					tcp_array.append(current_conn)
				except:
					continue

			else:
				# Item matched nothing
				pass

		self._connections_tcp = tcp_array
		self._connections_udp = udp_array
		self._shit_handler.error_log(0, "Found %s UDP Connections" % len(udp_array))
		self._shit_handler.error_log(0, "Found %s TCP Connections" % len(tcp_array))


	def get_runkey_from_reg(self):
		'''
		This will take all registry keys (and values) in CurrentVersion\Run
		and add them to the global array of self._startup_keys .
		:return:nothing
		'''
		startup_array = []

		regex_for_keys = "(.+)\s+:\s\(S\)\s(.+)"

		self._shit_handler.error_log(1, "Getting what's in the CurrentVersion\Run in Registry'")

		command = self._volname + " -f " + self._image_location + " --profile=" + self._image_type + " -K \"Software\Microsoft\Windows\CurrentVersion\Run\"" + " printkey"
		status, output = commands.getstatusoutput(command)

		output = output.split('\n')

		if len(output) == 0:
			self._shit_handler.error_log(1, "Finding startup keys command returned 0 results")
			return 1

		for line in output:
			temp = self.regex_search(line, regex_for_keys)
			try:
				temp = temp.groups()
				startup_array.append(temp[1])
			except:
				pass

		self._startup_keys = startup_array
		self._shit_handler.error_log(0, "Found %s startup keys" % len(self._startup_keys))


	def drivers(self):
		'''
		This function will return the list of all drivers found in memory image
		Regex here is shitty. Fix it if you dare.
		:return: nothing
		'''

		class driver_obj(object):
			def __init__(self):
				pass

		drivers_array = []
		regex_for_drivers = "(0x........)\s+(\d+)\s+(\d+)\s+(0x........)\s+([0-9xa-f]+)\s.....................([a-zA-Z0-9.]+)\s+(\\\\[A-Z0-9a-z\\\\-]+)"

		self._shit_handler.error_log(1, "Getting Drivers used by the system")

		command = self._volname + " -f " + self._image_location + " --profile=" + self._image_type + " driverscan"
		status, output = commands.getstatusoutput(command)

		output = output.split('\n')

		if len(output) == 0:
			return 1

		for driver in output:
			temp = self.regex_search(driver, regex_for_drivers)

			if temp is None:
				continue

			temp = temp.groups()
			current_driver = driver_obj()
			current_driver.offset = str(temp[0])
			current_driver.pointers = str(temp[1])
			current_driver.handlers = str(temp[2])
			current_driver.start = str(temp[3])
			current_driver.size = str(temp[4])
			current_driver.name = str(temp[5])
			current_driver.full_name = str(temp[6])
			drivers_array.append(current_driver)

		self._drivers = drivers_array
		self._shit_handler.error_log(0, "Found %s loaded drivers" % len(drivers_array))
