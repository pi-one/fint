#!/opt/local/bin/python

# coding: utf-8

"""
fint.py - v0.1 - 2012.03.15

Author : Jan Goebel - goebel@pi-one.net
Licence : GPL v2

Example Usage:
        # To find an executable that was compiled on a certain date
        python fint.py -m /path/to/search/ --compileTime 2012:03:25 -f *.exe

        # To find files with a certain size in bytes +- a variation of 10 bytes
        python fint.py -m /path/to/search/ --size 8109 --sizeVariation 10
"""

############################################################################
# General Information
############################################################################

__author__ = "jan goebel (goebel@pi-one.net)"
__version__ = "0.1"

############################################################################
# Imports
############################################################################

import sys
import os
import argparse
import hashlib
import fnmatch
import time
import struct

############################################################################

class pefile:
	"""
	read headers of a PE file
	"""
	def __init__(self, fn):
		self.filename = fn

	def checkFile(self):
		self.filecontent = None
		self.filelength = None
		self.readFileContent()
		self.peHeader = None
		if self.filelength>64:
			self.msdosDict = {}
			self.msdosHeader = self.filecontent[:64]
			if self.msdosHeader[0:2]==b'MZ':
				self.readMSDOSHeader(self.msdosHeader)
		else:
			#print("file too small")
			return False
		try:
			PESignature = self.filecontent[self.msdosDict['15_pPEHeader']:self.msdosDict['15_pPEHeader']+4]
		except:
			#print("no PE file!")
			return False
		else:
			if PESignature == '\x50\x45\x00\x00':
				self.peHeader = self.filecontent[self.msdosDict['15_pPEHeader']+4:self.msdosDict['15_pPEHeader']+4+20]
				self.peDict = {}
				self.readPEHeader(self.peHeader)
				self.peoptDict = {}
				self.peOptionalHeader = self.filecontent[self.msdosDict['15_pPEHeader']+4+20:self.msdosDict['15_pPEHeader']+4+20+self.peDict['06_sizeoptheader']]
				self.readPEOptHeader(self.peOptionalHeader)
				return True
			else:
				return False

	def readFileContent(self):
		"""
		read entire file
		"""
		fp = open(self.filename, 'rb')
		self.filecontent = fp.read()
		fp.close()
		self.filelength = len(self.filecontent)

	def readPEOptHeader(self, peOptionalHeader):
		self.peoptDict['01_optionalHeaderMagic'] = peOptionalHeader[0:2]
		if self.peoptDict['01_optionalHeaderMagic']=='\x0b\x01':
			self.peoptDict['01_optionalHeaderMagic']='PE32'
		elif self.peoptDict['01_optionalHeaderMagic']=='\x0b\x02':
			self.peoptDict['01_optionalHeaderMagic']='PE32+'
		self.peoptDict['02_majorlnkv'] = struct.unpack('b', peOptionalHeader[2])[0]
		self.peoptDict['03_minorlnkv'] = struct.unpack('b', peOptionalHeader[3])[0]
		self.peoptDict['04_codesize'] = struct.unpack('i', peOptionalHeader[4:8])[0]
		self.peoptDict['05_initsize'] = struct.unpack('i', peOptionalHeader[8:12])[0]
		self.peoptDict['06_uninitsize'] = struct.unpack('i', peOptionalHeader[12:16])[0]
		self.peoptDict['07_entrypoint'] = struct.unpack('i', peOptionalHeader[16:20])[0]
		self.peoptDict['08_baseofcode'] = struct.unpack('i', peOptionalHeader[20:24])[0]
		self.peoptDict['09_baseofdata'] = struct.unpack('i', peOptionalHeader[24:28])[0]
		self.peoptDict['10_imagebase'] = struct.unpack('i', peOptionalHeader[28:32])[0]
		self.peoptDict['11_sectionalignment'] = struct.unpack('i', peOptionalHeader[32:36])[0]
		self.peoptDict['12_filealignment'] = struct.unpack('I', peOptionalHeader[36:40])[0]
		self.peoptDict['13_majorop'] = struct.unpack('h', peOptionalHeader[40:42])[0]
		self.peoptDict['14_minorop'] = struct.unpack('h', peOptionalHeader[42:44])[0]
		self.peoptDict['15_majorimage'] = struct.unpack('h', peOptionalHeader[44:46])[0]
		self.peoptDict['16_minorimage'] = struct.unpack('h', peOptionalHeader[46:48])[0]
		self.peoptDict['17_majorsubver'] = struct.unpack('h', peOptionalHeader[48:50])[0]
		self.peoptDict['18_minorsubver'] = struct.unpack('h', peOptionalHeader[50:52])[0]
		self.peoptDict['19_win32verval'] = struct.unpack('i', peOptionalHeader[52:56])[0]
		self.peoptDict['20_sizeofimage'] = struct.unpack('i', peOptionalHeader[56:60])[0]
		self.peoptDict['21_sizeofheaders'] = struct.unpack('i', peOptionalHeader[60:64])[0]
		self.peoptDict['22_checksum'] = struct.unpack('i', peOptionalHeader[64:68])[0]
		self.peoptDict['23_subsystem'] = struct.unpack('h', peOptionalHeader[68:70])[0]
		self.peoptDict['24_DllCharacteristics'] = bin(int(hex(struct.unpack('h', peOptionalHeader[70:72])[0]), 16))[2:]
		self.peoptDict['25_SizeOfStackReserve'] = struct.unpack('i', peOptionalHeader[72:76])[0]
		self.peoptDict['26_SizeOfStackCommit'] = struct.unpack('i', peOptionalHeader[76:80])[0]
		self.peoptDict['27_SizeOfHeapReserve'] = struct.unpack('i', peOptionalHeader[80:84])[0]
		self.peoptDict['28_SizeOfHeapCommit'] = struct.unpack('i', peOptionalHeader[84:88])[0]
		self.peoptDict['29_loaderflags'] = struct.unpack('I', peOptionalHeader[88:92])[0]
		self.peoptDict['30_NumberOfRvaAndSizes'] = struct.unpack('I', peOptionalHeader[92:96])[0]
		self.peoptDict['31_imageDataDirectory'] = {}

	def readPEHeader(self, peHeader):
		self.peDict['01_machine'] = peHeader[0:2].encode('hex')
		if self.peDict['01_machine'] == '4c01':
			self.peDict['01_machine'] = "i386"
		self.peDict['02_numberofsections'] = struct.unpack('h', peHeader[2:4])[0]
		self.peDict['03_timedatestamp'] = struct.unpack('i', peHeader[4:8])[0]
		self.peDict['04_pSymbolTable'] = struct.unpack('I', peHeader[8:12])[0]
		self.peDict['05_numSymbols'] = struct.unpack('I', peHeader[12:16])[0]
		self.peDict['06_sizeoptheader'] = struct.unpack('h', peHeader[16:18])[0]
		self.peDict['07_chars'] = bin(int(hex(struct.unpack('H', peHeader[18:20])[0]), 16))

	def readMSDOSHeader(self, msdosHeader):
		self.msdosDict['01_magicnumber'] = struct.unpack('H', msdosHeader[0:2])[0]
		self.msdosDict['02_bytesLastPage'] = struct.unpack('H', msdosHeader[2:4])[0]
		self.msdosDict['03_pagesInFile'] = struct.unpack('H', msdosHeader[4:6])[0]
		self.msdosDict['04_numRelocs'] = struct.unpack('H', msdosHeader[6:8])[0]
		self.msdosDict['05_paragraphs'] = struct.unpack('H', msdosHeader[8:10])[0]
		self.msdosDict['06_minpara'] = struct.unpack('H', msdosHeader[10:12])[0]
		self.msdosDict['07_maxpara'] = struct.unpack('H', msdosHeader[12:14])[0]
		self.msdosDict['08_stackmod'] = struct.unpack('H', msdosHeader[14:16])[0]
		self.msdosDict['09_spregister'] = struct.unpack('H', msdosHeader[16:18])[0]
		self.msdosDict['10_chksum'] = struct.unpack('H', msdosHeader[18:20])[0]
		self.msdosDict['11_ipregister'] = struct.unpack('H', msdosHeader[20:22])[0]
		self.msdosDict['12_codemod'] = struct.unpack('H', msdosHeader[22:24])[0]
		self.msdosDict['13_offsetfirstreloc'] = struct.unpack('H', msdosHeader[24:26])[0]
		self.msdosDict['14_overlaynum'] = struct.unpack('H', msdosHeader[26:28])[0]
		self.msdosDict['15_pPEHeader'] = struct.unpack('I', msdosHeader[60:64])[0]

############################################################################

class fparser:
	"""
	parse filesystem and find certain files
	"""
	def __init__(self):
		self.running = True

	def quit(self):
		self.running = False

	def run(self, args):
		startDir = args.mountpoint
		print "Starting at directory: %s" % (startDir)
		depth = int(args.depth)
		if depth != -1:
			print "Directory depth: %s" % (depth)
		else:
			print "Directory depth: %s (unlimited)" % (depth)
		fileFilter = args.filter
		print "Filtering files: %s" % (fileFilter)

		resultSet = self.search(startDir, depth, fileFilter, args)
		return None

	def processFile(self, root, fn, md5):
		cpath = os.path.join(root, fn)
		h = hashlib.sha256()
		with open(cpath, 'rb') as f:
			for chunk in iter(lambda: f.read(8192), ''):
				h.update(chunk)
		sha256 = h.hexdigest()
		extension = os.path.splitext(cpath)[1][1:]
		stats = os.stat(cpath)
		size = int(stats.st_size)
		atime = int(stats.st_atime)
		mtime = int(stats.st_mtime)
		ctime = int(stats.st_ctime)
		pe = pefile(cpath)
		peRes = pe.checkFile()
		if peRes:
			compileTime = pe.peDict['03_timedatestamp']
		else:
			compileTime = 0
		return [root, fn, extension, size, md5, sha256, atime, mtime, ctime, compileTime]

	def checkItem(self, item, args):
		resVal = False
		""" consider size only """
		if args.size!=0 and args.md5=='None' and args.compileTime=='None':
			if args.size == item[3] or (args.size-args.sizeVariation <= item[3] <= args.size+args.sizeVariation):
				resVal = True
		""" consider size and md5 """
		if args.size!=0 and args.md5!='None' and args.compileTime=='None':
			if args.size == item[3] or (args.size-args.sizeVariation <= item[3] <= args.size+args.sizeVariation) and args.md5 == item[4]:
				resVal = True
		""" consider size and md5 and compileTime """
		if args.size!=0 and args.md5!='None' and args.compileTime!='None':
			tobj = time.gmtime(item[9])
			cobj = args.compileTime.split(':')
			if args.size == item[3] or (args.size-args.sizeVariation <= item[3] <= args.size+args.sizeVariation) and args.md5 == item[4] and int(tobj.tm_year) == int(cobj[0]) and int(tobj.tm_mon) == int(cobj[1]) and int(tobj.tm_mday) == int(cobj[2]):
				resVal = True
		""" consider size and compileTime """
		if args.size!=0 and args.md5=='None' and args.compileTime!='None':
			tobj = time.gmtime(item[9])
			cobj = args.compileTime.split(':')
			if args.size == item[3] or (args.size-args.sizeVariation <= item[3] <= args.size+args.sizeVariation) and int(tobj.tm_year) == int(cobj[0]) and int(tobj.tm_mon) == int(cobj[1]) and int(tobj.tm_mday) == int(cobj[2]):
				resVal = True
		""" consider md5 and compileTime """
		if args.size==0 and args.md5=='None' and args.compileTime!='None':
			tobj = time.gmtime(item[9])
			cobj = args.compileTime.split(':')
			if int(tobj.tm_year) == int(cobj[0]) and int(tobj.tm_mon) == int(cobj[1]) and int(tobj.tm_mday) == int(cobj[2]):
				resVal = True
		""" consider compileTime only """
		if args.size==0 and args.md5=='None' and args.compileTime!='None':
			tobj = time.gmtime(item[9])
			cobj = args.compileTime.split(':')
			if int(tobj.tm_year) == int(cobj[0]) and int(tobj.tm_mon) == int(cobj[1]) and int(tobj.tm_mday) == int(cobj[2]):
				resVal = True
		""" consider compileYear only """
		if args.size==0 and args.md5=='None' and args.compileTime=='None' and args.compileYear!='None' and args.compileMonth=='None':
			tobj = time.gmtime(item[9])
			cobj = args.compileYear
			if int(tobj.tm_year) == int(cobj):
				resVal = True
		""" consider compileMonth only """
		if args.size==0 and args.md5=='None' and args.compileTime=='None' and args.compileYear=='None' and args.compileMonth!='None':
			tobj = time.gmtime(item[9])
			cobj = args.compileMonth
			if int(tobj.tm_mon) == int(cobj):
				resVal = True
		""" consider compileMonth and compileYear only """
		if args.size==0 and args.md5=='None' and args.compileTime=='None' and args.compileYear!='None' and args.compileMonth!='None':
			tobj = time.gmtime(item[9])
			if int(tobj.tm_mon) == int(args.compileMonth) and int(tobj.tm_year) == int(args.compileYear):
				resVal = True
		""" consider md5 only """
		if args.size==0 and args.md5!='None' and args.compileTime=='None' and args.compileMonth=='None':
			if args.md5 == item[4]:
				resVal = True
		""" no specific filters then display all """
		if args.size==0 and args.md5=='None' and args.compileTime=='None' and args.compileYear=='None' and args.compileMonth=='None':
			resVal = True
		return resVal

	def search(self, startDir, depth, fileFilter, args):
		"""
		recursively traverse thru the filesystem
		"""
		resultSet = []
		curDepth = 0
		startDepth = startDir.count(os.sep)
		for root, dirs, files in os.walk(startDir):
			if not self.running:
				break
			curDepth = root.count(os.sep) - startDepth
			if depth>=0 and curDepth>=depth:
				dirs[:] = []
			for fn in files:
				if fnmatch.fnmatch(fn, fileFilter):
					h = hashlib.md5()
					try:
						with open(os.path.join(root, fn),'rb') as f:
							for chunk in iter(lambda: f.read(8192), ''):
								h.update(chunk)
						fingerprint = h.hexdigest()
					except IOError, e:
						fingerprint = None
					#if fingerprint in hashList:
					item = self.processFile(root, fn, fingerprint)
					res = self.checkItem( item, args )
					if res:
						resultSet.append( item )
						### path filename md5fingerprint
						print "\t %s" % (item)
					del h
		return resultSet

############################################################################

if __name__ == '__main__':
	""" set working directory """
	workdir = sys.path[0]
	os.chdir(workdir)
	""" parse arguments """
	parser = argparse.ArgumentParser(description='find interesting files')
	parser.add_argument('-d', '--depth', type=int, default=-1, help='traverse directories to depth (default: no limit)')
	parser.add_argument('-m', '--mountpoint', required=True, help='starting directory of search')
	parser.add_argument('-f', '--filter', default='*.*', help='file filter ("*.*", "*.exe", ...)')
	parser.add_argument('-s', '--size', type=int, default=0, help='search for files of certain size (bytes)')
	parser.add_argument('--sizeVariation', type=int, default=0, help='file size may vary by certain number of bytes')
	parser.add_argument('--md5', default='None', help='search for files with md5 fingerprint')
	parser.add_argument('--compileTime', default='None', help='search for files compiled on date (year:month:day)')
	parser.add_argument('--compileYear', default='None', help='search for files compiled on year')
	parser.add_argument('--compileMonth', default='None', help='search for files compiled on month')
	args = parser.parse_args()
	""" set absolute search path """
	searchPath = os.path.abspath( args.mountpoint )
	if not os.path.exists(searchPath):
		print "mountpoint does not exist!"
		sys.exit(255)
	args.mountpoint = searchPath
	print args
	""" create parser """
	p = fparser()
	p.run(args)

