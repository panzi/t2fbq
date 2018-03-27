#!/usr/bin/env python
# coding=UTF-8
#
# Copyright (c) 2014 Mathias Panzenböck
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

from __future__ import with_statement, division, print_function

import os
import sys
import struct
from collections import OrderedDict
from io import BytesIO

try:
	from lzf import decompress
except ImportError:
	HAS_LZF = False
else:
	HAS_LZF = True

try:
	import llfuse
except ImportError:
	HAS_LLFUSE = False
else:
	HAS_LLFUSE = True

HAS_STAT_NS = hasattr(os.stat_result, 'st_atime_ns')

__all__ = 'read_index', 'unpack', 'unpack_files', 'print_list', 'mount'

# for Python < 3.3 and Windows
def highlevel_sendfile(outfile,infile,offset,size):
	infile.seek(offset,0)
	while size > 0:
		if size > 2 ** 20:
			chunk_size = 2 ** 20
		else:
			chunk_size = size
		size -= chunk_size
		data = infile.read(chunk_size)
		outfile.write(data)
		if len(data) < chunk_size:
			raise IOError("unexpected end of file")

if hasattr(os, 'sendfile'):
	def sendfile(outfile,infile,offset,size):
		try:
			out_fd = outfile.fileno()
			in_fd  = infile.fileno()
		except:
			highlevel_sendfile(outfile,infile,offset,size)
		else:
			# size == 0 has special meaning for some sendfile implentations
			if size > 0:
				os.sendfile(out_fd, in_fd, offset, size)
else:
	sendfile = highlevel_sendfile

def read_index(stream):
	buf = stream.read(12)
	version, entry_count, index_size = struct.unpack('<III',buf)
	data_offset = index_size + 12

	if version != 2:
		raise ValueError("unsupported format version: %d" % version)
	
	namebuf = BytesIO()
	i = 0
	while i < entry_count:
		namebuf.seek(0, 0)
		namebuf.truncate(0)
		while True:
			byte = stream.read(1)

			if not byte:
				raise IOError("unexpected end of stream")

			if byte == b'\x00':
				break

			namebuf.write(byte)
		name = namebuf.getvalue().decode('ascii').replace('/',os.path.sep)
		buf = stream.read(17)
		offset, nocompr, uncompressed_size, compressed_size, chksum = struct.unpack('<IBIII',buf)
		compr = nocompr == 0
		if not compr:
			if compressed_size != uncompressed_size:
				raise ValueError("not compressed but compressed size (%u) != uncompressed size (%u)" %
					(compressed_size, uncompressed_size))
			compressed_size = None

		pos = stream.tell()
		if pos > data_offset:
			raise ValueError("index bleeds into data section. pos = %u, data_offset = %u, i = %u, entry_count = %u" %
				(pos, data_offset, i, entry_count))

		yield name, data_offset + offset, uncompressed_size, compressed_size, chksum
		stream.seek(pos, 0)
		i += 1

def unpack(stream,outdir=".",callback=lambda name: None):
	# convert to list to reduce seeking in file and completely parse index before writing any files
	for name, offset, size, csize, chksum in list(read_index(stream)):
		unpack_file(stream,name,offset,size,csize,outdir,callback)

def shall_unpack(paths,name):
	path = name.split(os.path.sep)
	for i in range(1,len(path)+1):
		prefix = os.path.join(*path[0:i])
		if prefix in paths:
			return True
	return False

def unpack_files(stream,files,outdir=".",callback=lambda name: None):
	# convert to list to reduce seeking in file and completely parse index before writing any files
	for name, offset, size, csize, chksum in list(read_index(stream)):
		if shall_unpack(files,name):
			unpack_file(stream,name,offset,size,csize,outdir,callback)

def unpack_file(stream,name,offset,size,csize,outdir=".",callback=lambda name: None):
	prefix, name = os.path.split(name)
	prefix = os.path.join(outdir,prefix)
	if not os.path.exists(prefix):
		os.makedirs(prefix)
	name = os.path.join(prefix,name)
	callback(name)
	if csize is None:
		with open(name,"wb") as fp:
			sendfile(fp,stream,offset,size)
	else:
		stream.seek(offset, 0)
		cdata = stream.read(csize)
		if len(cdata) != csize:
			raise IOError("unexpected end of file while reading data of entry: %s" % name)

		data = decompress(cdata,size)
		if data is None or len(data) != size:
			raise IOError("error uncompressing entry: %s" % name)

		with open(name,"wb") as fp:
			fp.write(data)

def human_size(size):
	if size < 2 ** 10:
		return str(size)
	
	elif size < 2 ** 20:
		size = "%.1f" % (size / 2 ** 10)
		unit = "K"

	elif size < 2 ** 30:
		size = "%.1f" % (size / 2 ** 20)
		unit = "M"

	elif size < 2 ** 40:
		size = "%.1f" % (size / 2 ** 30)
		unit = "G"

	elif size < 2 ** 50:
		size = "%.1f" % (size / 2 ** 40)
		unit = "T"

	elif size < 2 ** 60:
		size = "%.1f" % (size / 2 ** 50)
		unit = "P"

	elif size < 2 ** 70:
		size = "%.1f" % (size / 2 ** 60)
		unit = "E"

	elif size < 2 ** 80:
		size = "%.1f" % (size / 2 ** 70)
		unit = "Z"

	else:
		size = "%.1f" % (size / 2 ** 80)
		unit = "Y"
	
	if size.endswith(".0"):
		size = size[:-2]
	
	return size+unit

def print_list(stream,details=False,human=False,delim="\n",sort_func=None,out=sys.stdout):
	index = read_index(stream)

	if sort_func:
		index = sorted(index,cmp=sort_func)

	if details:
		if human:
			size_to_str = human_size
		else:
			size_to_str = str

		count = 0
		sum_size = 0
		out.write("    Offset         Size  Compr. Size  Compr.  Checksum  Name%s" % delim)
		for name, offset, size, csize, chksum in index:
			if csize is None:
				out.write("%10u  %11s            -          %08x  %s%s" % (
					offset, size_to_str(size), chksum, name, delim))
			else:
				out.write("%10u  %11s  %11s  LZF     %08x  %s%s" % (
					offset, size_to_str(size), size_to_str(csize), chksum, name, delim))
			count += 1
			sum_size += size
		out.write("%d file(s) (%s) %s" % (count, size_to_str(sum_size), delim))
	else:
		for item in index:
			out.write("%s%s" % (item[0], delim))

SORT_ALIASES = {
	"s": "size",
	"S": "-size",
	"c": "csize",
	"C": "-csize",
	"o": "offset",
	"O": "-offset",
	"n": "name",
	"N": "-name"
}

# for Python 3
if not hasattr(__builtins__,'cmp'):
	def cmp(a, b):
		return (a > b) - (a < b)

CMP_FUNCS = {
	"size":  lambda lhs, rhs: cmp(lhs[2], rhs[2]),
	"-size": lambda lhs, rhs: cmp(rhs[2], lhs[2]),
	
	"csize":  lambda lhs, rhs: cmp(lhs[3] or 0, rhs[3] or 0),
	"-csize": lambda lhs, rhs: cmp(rhs[3] or 0, lhs[3] or 0),

	"offset":  lambda lhs, rhs: cmp(lhs[1], rhs[1]),
	"-offset": lambda lhs, rhs: cmp(rhs[1], lhs[1]),

	"name":  lambda lhs, rhs: cmp(lhs[0], rhs[0]),
	"-name": lambda lhs, rhs: cmp(rhs[0], lhs[0])
}

def sort_func(sort):
	cmp_funcs = []
	for key in sort.split(","):
		key = SORT_ALIASES.get(key,key)
		try:
			func = CMP_FUNCS[key]
		except KeyError:
			raise ValueError("unknown sort key: "+key)
		cmp_funcs.append(func)

	def do_cmp(lhs,rhs):
		for cmp_func in cmp_funcs:
			i = cmp_func(lhs,rhs)
			if i != 0:
				return i
		return 0

	return do_cmp


if HAS_LLFUSE:
	import errno
	import weakref
	import stat
	import mmap

	class Archive(object):
		__slots__ = 'file', 'stat', 'data'

		def __init__(self,file):
			self.file = file
			self.stat = os.fstat(file.fileno())
			self.data = None

		def mmap(self):
			self.file.seek(0, 0)
			self.data = mmap.mmap(self.file.fileno(), 0, access=mmap.ACCESS_READ)

		def close(self):
			if self.data:
				self.data.close()
				self.data = None
			self.file.close()
			
		def __repr__(self):
			return 'Archive(file=%r)' % self.file

	class Entry(object):
		__slots__ = 'inode','_parent','stat','__weakref__'

		def __init__(self,inode,parent=None):
			self.inode   = inode
			self.parent  = parent
			self.stat    = None

		@property
		def parent(self):
			return self._parent() if self._parent is not None else None

		@parent.setter
		def parent(self,parent):
			self._parent = weakref.ref(parent) if parent is not None else None

	class Dir(Entry):
		__slots__ = 'children',

		def __init__(self,inode,children=None,parent=None):
			Entry.__init__(self,inode,parent)
			if children is None:
				self.children = OrderedDict()
			else:
				self.children = children
				for child in children.values():
					child.parent = self

		def __repr__(self):
			return 'Dir(indoe=%r, children=%r)' % (self.inode, self.children)

	class File(Entry):
		__slots__ = 'archive', 'offset', 'size', 'csize', 'chksum', 'opencount', 'cache'

		def __init__(self,archive,inode,offset,size,csize,chksum,parent=None):
			Entry.__init__(self,inode,parent)
			self.archive   = archive
			self.offset    = offset
			self.size      = size
			self.csize     = csize
			self.chksum     = chksum
			self.opencount = 0
			self.cache     = None

		def open(self):
			self.opencount += 1

		def close(self):
			count = self.opencount - 1
			if count <= 0:
				self.opencount = 0
				self.cache     = None
			else:
				self.opencount = count
		
		def read(self,offset,length):
			if offset > self.size:
				return bytes()

			if self.csize is None:
				i = self.offset + offset
				j = i + min(self.size - offset, length)
				return self.archive.data[i:j]

			if self.cache is None:
				self.cache = decompress(self.archive.data[self.offset:self.offset+self.csize], self.size)
				if self.cache is None or len(self.cache) != self.size:
					self.cache = None
					raise llfuse.FUSEError(errno.EIO)

			return self.cache[offset:offset+length]

		@property
		def compressed(self):
			return self.csize is not None

		def __repr__(self):
			return 'File(archive=%r, inode=%r, offset=%r, size=%r, csize=%r, chksum=0x%08x)' % (
				self.archive, self.inode, self.offset, self.size, self.csize, self.chksum)

	DIR_SELF   = '.'.encode(sys.getfilesystemencoding())
	DIR_PARENT = '..'.encode(sys.getfilesystemencoding())

	class Operations(llfuse.Operations):
		__slots__ = 'archives','root','inodes'

		def __init__(self, archives):
			llfuse.Operations.__init__(self)
			self.archives = [Archive(archive) for archive in archives]
			self.root     = Dir(llfuse.ROOT_INODE)
			self.inodes   = {self.root.inode: self.root}
			self.root.parent = self.root

			encoding = sys.getfilesystemencoding()
			inode = self.root.inode + 1
			for archive in self.archives:
				for filename, offset, size, csize, chksum in read_index(archive.file):
					path = filename.split(os.path.sep)
					path, name = path[:-1], path[-1]
					enc_name = name.encode(encoding)
					name, ext = os.path.splitext(name)

					parent = self.root
					for i, comp in enumerate(path):
						comp = comp.encode(encoding)
						try:
							entry = parent.children[comp]
						except KeyError:
							entry = parent.children[comp] = self.inodes[inode] = Dir(inode, parent=parent)
							inode += 1
						
						if type(entry) is not Dir:
							raise ValueError("name conflict in archive: %r is not a directory" % os.path.join(*path[:i+1]))

						parent = entry

					oldentry = parent.children.get(enc_name,None)
					if oldentry:
						if oldentry.archive is archive:
							i = 0
							while enc_name in parent.children:
								sys.stderr.write("Warning: doubled name in archive: %s\n" % filename)
								i += 1
								enc_name = ("%s~%d%s" % (name, i, ext)).encode(encoding)
						else:
							del self.inodes[oldentry.inode]

					parent.children[enc_name] = self.inodes[inode] = File(archive, inode, offset, size,
					                                                      csize, chksum, parent)
					inode += 1

				archive.mmap()

			# cache entry attributes
			for inode in self.inodes:
				entry = self.inodes[inode]
				entry.stat = self._getattr(entry)

		def destroy(self):
			for archive in self.archives:
				archive.close()

		def lookup(self, parent_inode, name, ctx):
			try:
				if name == DIR_SELF:
					entry = self.inodes[parent_inode]

				elif name == DIR_PARENT:
					entry = self.inodes[parent_inode].parent

				else:
					entry = self.inodes[parent_inode].children[name]

			except KeyError:
				raise llfuse.FUSEError(errno.ENOENT)
			else:
				return entry.stat

		def _getattr(self, entry):
			attrs = llfuse.EntryAttributes()

			attrs.st_ino        = entry.inode
			attrs.st_rdev       = 0
			attrs.generation    = 0
			attrs.entry_timeout = 300
			attrs.attr_timeout  = 300

			if type(entry) is Dir:
				nlink = 2 if entry is not self.root else 1
				size  = 5

				for name, child in entry.children.items():
					size += len(name) + 1
					if type(child) is Dir:
						nlink += 1

				attrs.st_mode  = stat.S_IFDIR | 0o555
				attrs.st_nlink = nlink
				attrs.st_size  = size

			else:
				attrs.st_nlink = 1
				attrs.st_mode  = stat.S_IFREG | 0o444
				attrs.st_size  = entry.csize if entry.csize is not None else entry.size

			arch_st = entry.archive.stat
			attrs.st_uid     = arch_st.st_uid
			attrs.st_gid     = arch_st.st_gid
			attrs.st_blksize = arch_st.st_blksize
			attrs.st_blocks  = 1 + ((attrs.st_size - 1) // attrs.st_blksize) if attrs.st_size != 0 else 0
			if HAS_STAT_NS:
				attrs.st_atime_ns = arch_st.st_atime_ns
				attrs.st_mtime_ns = arch_st.st_mtime_ns
				attrs.st_ctime_ns = arch_st.st_ctime_ns
			else:
				attrs.st_atime_ns = int(arch_st.st_atime * 1000)
				attrs.st_mtime_ns = int(arch_st.st_mtime * 1000)
				attrs.st_ctime_ns = int(arch_st.st_ctime * 1000)

			return attrs

		def getattr(self, inode, ctx):
			try:
				entry = self.inodes[inode]
			except KeyError:
				raise llfuse.FUSEError(errno.ENOENT)
			else:
				return entry.stat

		def access(self, inode, mode, ctx):
			try:
				entry = self.inodes[inode]
			except KeyError:
				raise llfuse.FUSEError(errno.ENOENT)
			else:
				st_mode = 0o555 if type(entry) is Dir else 0o444
				return (st_mode & mode) == mode

		def opendir(self, inode, ctx):
			try:
				entry = self.inodes[inode]
			except KeyError:
				raise llfuse.FUSEError(errno.ENOENT)
			else:
				if type(entry) is not Dir:
					raise llfuse.FUSEError(errno.ENOTDIR)

				return inode

		def readdir(self, inode, offset):
			try:
				entry = self.inodes[inode]
			except KeyError:
				raise llfuse.FUSEError(errno.ENOENT)
			else:
				if type(entry) is not Dir:
					raise llfuse.FUSEError(errno.ENOTDIR)

				names = list(entry.children)[offset:] if offset > 0 else entry.children
				for name in names:
					child = entry.children[name]
					yield name, child.stat, child.inode

		def releasedir(self, fh):
			pass

		def statfs(self, ctx):
			attrs = llfuse.StatvfsData()

			attrs.f_bsize  = 4096
			attrs.f_frsize = 4096
			attrs.f_blocks = sum(archive.stat.st_blocks for archive in self.archives)
			attrs.f_bfree  = 0
			attrs.f_bavail = 0

			attrs.f_files  = len(self.inodes)
			attrs.f_ffree  = 0
			attrs.f_favail = 0

			return attrs

		def open(self, inode, flags, ctx):
			try:
				entry = self.inodes[inode]
			except KeyError:
				raise llfuse.FUSEError(errno.ENOENT)
			else:
				if type(entry) is Dir:
					raise llfuse.FUSEError(errno.EISDIR)

				if flags & 3 != os.O_RDONLY:
					raise llfuse.FUSEError(errno.EACCES)

				entry.open()
				return inode

		def read(self, fh, offset, length):
			try:
				entry = self.inodes[fh]
			except KeyError:
				raise llfuse.FUSEError(errno.ENOENT)
			else:
				return entry.read(offset, length)

		def release(self, fh):
			try:
				entry = self.inodes[fh]
			except KeyError:
				pass
			else:
				entry.close()

	# based on http://code.activestate.com/recipes/66012/
	def deamonize(stdout='/dev/null', stderr=None, stdin='/dev/null'):
		# Do first fork.
		try:
			pid = os.fork()
			if pid > 0:
				sys.exit(0) # Exit first parent.
		except OSError as e:
			sys.stderr.write("fork #1 failed: (%d) %s\n" % (e.errno, e.strerror))
			sys.exit(1)

		# Decouple from parent environment.
		os.chdir("/")
		os.umask(0)
		os.setsid()

		# Do second fork.
		try:
			pid = os.fork()
			if pid > 0:
				sys.exit(0) # Exit second parent.
		except OSError as e:
			sys.stderr.write("fork #2 failed: (%d) %s\n" % (e.errno, e.strerror))
			sys.exit(1)

		# Open file descriptors
		if not stderr:
			stderr = stdout

		si = open(stdin, 'r')
		so = open(stdout, 'a+')
		se = open(stderr, 'a+')

		# Redirect standard file descriptors.
		sys.stdout.flush()
		sys.stderr.flush()

		os.close(sys.stdin.fileno())
		os.close(sys.stdout.fileno())
		os.close(sys.stderr.fileno())

		os.dup2(si.fileno(), sys.stdin.fileno())
		os.dup2(so.fileno(), sys.stdout.fileno())
		os.dup2(se.fileno(), sys.stderr.fileno())

	def open_multi(paths,mode="rb"):
		files = []
		exc = None
		for path in paths:
			try:
				files.append(open(path,mode))
			except Exception as e:
				exc = e
				break

		if exc is None:
			return files

		close_multi(files)

		raise exc

	def close_multi(files):
		for fp in files:
			try:
				fp.close()
			except Exception as e:
				sys.stderr.write("%s\n" % e)

	def mount(archives,mountpt,foreground=False,debug=False):
		archives = [os.path.abspath(archive) for archive in archives]
		mountpt = os.path.abspath(mountpt)
		files = open_multi(archives)

		try:
			ops = Operations(files)
			args = ['fsname=t2fbq', 'subtype=t2fbq', 'ro']

			if debug:
				foreground = True
				args.append('debug')

			if not foreground:
				deamonize()

			llfuse.init(ops, mountpt, args)
			try:
				llfuse.main()
			finally:
				llfuse.close()

		finally:
			close_multi(files)

def main(argv):
	import argparse

	# from https://gist.github.com/sampsyo/471779
	class AliasedSubParsersAction(argparse._SubParsersAction):

		class _AliasedPseudoAction(argparse.Action):
			def __init__(self, name, aliases, help):
				dest = name
				if aliases:
					dest += ' (%s)' % ','.join(aliases)
				sup = super(AliasedSubParsersAction._AliasedPseudoAction, self)
				sup.__init__(option_strings=[], dest=dest, help=help) 

		def add_parser(self, name, **kwargs):
			if 'aliases' in kwargs:
				aliases = kwargs['aliases']
				del kwargs['aliases']
			else:
				aliases = []

			parser = super(AliasedSubParsersAction, self).add_parser(name, **kwargs)

			# Make the aliases work.
			for alias in aliases:
				self._name_parser_map[alias] = parser
			# Make the help text reflect them, first removing old help entry.
			if 'help' in kwargs:
				help = kwargs.pop('help')
				self._choices_actions.pop()
				pseudo_action = self._AliasedPseudoAction(name, aliases, help)
				self._choices_actions.append(pseudo_action)

			return parser

	parser = argparse.ArgumentParser(description='unpack, list and mount Trine 2 .fbq archives')
	parser.register('action', 'parsers', AliasedSubParsersAction)
	parser.set_defaults(print0=False,verbose=False)

	subparsers = parser.add_subparsers(metavar='command')

	unpack_parser = subparsers.add_parser('unpack',aliases=('x',),help='unpack archive')
	unpack_parser.set_defaults(command='unpack')
	unpack_parser.add_argument('-C','--dir',type=str,default='.',
		help='directory to write unpacked files')
	add_common_args(unpack_parser)
	unpack_parser.add_argument('files', metavar='file', nargs='*', help='files and directories to unpack')

	list_parser = subparsers.add_parser('list',aliases=('l',),help='list archive contens')
	list_parser.set_defaults(command='list')
	list_parser.add_argument('-u','--human-readable',dest='human',action='store_true',default=False,
		help='print human readable file sizes')
	list_parser.add_argument('-d','--details',action='store_true',default=False,
		help='print file offsets and sizes')
	list_parser.add_argument('-s','--sort',dest='sort_func',metavar='KEYS',type=sort_func,default=None,
		help='sort file list. Comma seperated list of sort keys. Keys are "size", "offset", and "name". '
		     'Prepend "-" to a key name to sort in descending order.')
	add_common_args(list_parser)

	mount_parser = subparsers.add_parser('mount',aliases=('m',),help='fuse mount archive')
	mount_parser.set_defaults(command='mount')
	mount_parser.add_argument('-d','--debug',action='store_true',default=False,
		help='print debug output (implies -f)')
	mount_parser.add_argument('-f','--foreground',action='store_true',default=False,
		help='foreground operation')
	mount_parser.add_argument('archives', nargs='+', help='Trine 2 .fbq archive')
	mount_parser.add_argument('mountpt', help='mount point')

	args = parser.parse_args(argv)

	delim = '\0' if args.print0 else '\n'

	if args.verbose:
		callback = lambda name: sys.stdout.write("%s%s" % (name, delim))
	else:
		callback = lambda name: None

	if args.command == 'list':
		with open(args.archive,"rb") as stream:
			print_list(stream,args.details,args.human,delim,args.sort_func)
	
	elif args.command == 'unpack':
		if not HAS_LZF:
			raise ValueError("the lzf python module is needed for this feature")

		with open(args.archive,"rb") as stream:
			if args.files:
				unpack_files(stream,set(name.strip(os.path.sep) for name in args.files),args.dir,callback)
			else:
				unpack(stream,args.dir,callback)

	elif args.command == 'mount':
		if not HAS_LZF:
			raise ValueError("the lzf python module is needed for this feature")

		if not HAS_LLFUSE:
			raise ValueError('the llfuse python module is needed for this feature')

		mount(args.archives,args.mountpt,args.foreground,args.debug)

	else:
		raise ValueError('unknown command: %s' % args.command)

def add_common_args(parser):
	parser.add_argument('archive', help='Trine 2 .fbq archive')
	parser.add_argument('-0','--print0',action='store_true',default=False,
		help='seperate file names with nil bytes')
	parser.add_argument('-v','--verbose',action='store_true',default=False,
		help='print verbose output')

if __name__ == '__main__':
	try:
		main(sys.argv[1:])
	except Exception as exc:
		sys.stderr.write("%s\n" % exc)
		sys.exit(1)
