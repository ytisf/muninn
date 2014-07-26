#!/usr/bin/env python

import sys

try:
	from prettytable import PrettyTable
except ImportError, e:
	print "The module 'prettytable' is not installed."
	print "Please use: "
	print "\tsudo pip install prettytable"
	sys.exit(1)

import imports.error_handler


class Secretary():
	def __init__(self):
		self._shit_handler = imports.error_handler.Shit_Handler()
		self._casenumber = ""
		self._title = ""
		self._file_handler = ""
		self._br = "\n###########################################################################\n\n"


	def InitiateDocument(self, casenumber, date, filename, md5, imagetype):
		self._shit_handler.error_log(1, "Starting to create document at CS-%s.txt" % casenumber)
		self._title = "Memory Report - CS-%s" % casenumber
		self._file_handler = open("CS%s.txt" % casenumber, 'wb')
		self._file_handler.write("###########################################################################\n")
		self._file_handler.write("###########################################################################\n")
		self._file_handler.write("\t\t\t#%s\n" % self._title)
		self._file_handler.write("###########################################################################\n")
		self._file_handler.write("###########################################################################\n")
		self._file_handler.write("\n##Background:\n")
		self._file_handler.write("\tCase Number:\t%s\n" % casenumber)
		self._file_handler.write("\tCase Date:\t%s\n" % date)
		self._file_handler.write("\tImage Name:\t%s\n" % filename)
		self._file_handler.write("\tImage Type:\t%s\n" % imagetype)
		self._file_handler.write("\tMD5 Digest:\t%s\n" % md5)
		self._file_handler.write("\tGenerated using lazy_volatility by tisf\n")
		self._file_handler.write("%s" % self._br)

	def print_title(self, title, level):
		'''
		:param title: Text to be in the header
		:param level: level of the header
		:return: nothing
		'''

		printme = "|"
		printme += level * "#"
		printme += " %s |" % title

		lower = "+"
		lower += "-" * (len(printme) - 1)
		lower += "+"

		self._file_handler.write("\n%s\n" % lower)
		self._file_handler.write("%s\n" % printme)
		self._file_handler.write("%s\n\n" % lower)


	def print_table(self, headers, body, sort_by):
		'''
		:param headers: will contain headers of the table to print
		:param body: actual array to print in the table
		:param sort_by: the main column which the table will be sorted by
		:return: returns nothing
		'''
		x = PrettyTable(headers)
		x.sortby = sort_by
		x.align[sort_by] = "l"
		x.padding_width = 1

		for row in body:
			x.add_row(row)

		self._file_handler.write("%s\n" % x)
		self._file_handler.write("%s" % self._br)

	def save(self):
		self._file_handler.close()
		self._shit_handler.error_log(0, "Report CS-%s.txt is ready!" % self._casenumber)






