t2fbq
=====

Unpack, list and mount Trine 2 .fbq archives.

Basic usage:

	t2fbq.py list <archive>                              - list contens of .fbq archive
	t2fbq.py unpack <archive>                            - extract .fbq archive
	t2fbq.py mount <archive> [archive]... <mount-point>  - mount archive as read-only file system

The `mount` command depends on the [llfuse](https://code.google.com/p/python-llfuse/)
Python package and the `unpack` and `mount` commands depend on the
[lzf](https://github.com/teepark/python-lzf) Python package. If these packages are not
available the rest is still working.

This script is compatible with Python 2.7 and 3 (tested with 2.7.5 and 3.3.2).

File Format
-----------

Byte order is little endian and the character encoding of file names seems to
be ASCII (or ISO-8859-1/UTF-8 that coincidentally only uses ASCII compatiple
characters).

Data might be compressed using the LZF compression algorithm.

Basic layout:

 * File Header
 * Index Records
 * Data Records

### File Header

	Offset  Size  Type      Description
	     0     4  uint32_t  version (2)
	     4     4  uint32_t  number of entries
	     8     4  uint32_t  size of index

### Index Record

	Offset  Size  Type      Description
	     0     N  char[N]   null terminated absolute file name ('/' is path separator)
	     N     4  uint32_t  data offset relative to end of index
	   N+4     1  bool      not compressed flag (1 if data is not compressed, 0 if compressed)
	   N+5     4  uint32_t  uncompressed size
	   N+9     4  uint32_t  compressed size
	  N+13     4  uint32_t  chceksum of unknown algorithm?

Related Projects
----------------

 * [fezpak](https://github.com/panzi/fezpak): pack, unpack, list and mount FEZ .pak archives
 * [psypkg](https://github.com/panzi/psypkg): pack, unpack, list and mount Psychonauts .pkg archives
 * [bgebf](https://github.com/panzi/bgebf): unpack, list and mount Beyond Good and Evil .bf archives
 * [unvpk](https://bitbucket.org/panzi/unvpk): extract, list, check and mount Valve .vpk archives
 * [u4pak](https://github.com/panzi/u4pak): unpack, list and mount Unreal Engine 4 .pak archives

BSD License
-----------
Copyright (c) 2014 Mathias Panzenböck

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
