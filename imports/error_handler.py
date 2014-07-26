#!/usr/bin/env python

import sys

# This is the file which handles the shit and what happens when shit happens

class Shit_Handler():
	def __init__(self):
		self._errorlogger = ""

	def error_log(self, code, message):
		'''
		This function is just used to document things.
		Maybe later we'll add a write to file options or
		actually consider the verbosity option seriously...
		Codes:
		# 0 = good
		# 1 = information
		# 2 = warning
		# 3 = error
		# 4 = critical
		:param code: Code of the error (from 0-good to 4-critical).
		:param message: The message to be logged along with error code.
		:return:Nothing
		'''

		class bcolors:
			HEADER = '\033[95m'
			OKBLUE = '\033[94m'
			OKGREEN = '\033[92m'
			WARNING = '\033[93m'
			FAIL = '\033[91m'
			ENDC = '\033[0m'


		if code == 0:
			# This system cannot handle good feedback
			print bcolors.OKGREEN + "[+]\t" + bcolors.ENDC + str(message)

		elif code == 1:
			# Give out information:
			print bcolors.OKBLUE + "[+]\t" + bcolors.ENDC + str(message)  # Avoid too much information


		elif code == 2:
			# Enter warning code here
			pass

		elif code == 3:
			# Enter error code here
			print bcolors.WARNING + "[*]\t" + bcolors.ENDC + message

		elif code == 4:
			print bcolors.FAIL + "\n\n[!]\t" + bcolors.ENDC + message
			sys.exit(0)

		else:
			''' For those who can't even handle a shit_handler... '''
			print bcolors.FAIL + "\n\n[!]\t" + bcolors.ENDC + "You fucked up the shit handler! You're fucking terrible!"
			sys.exit(1)

