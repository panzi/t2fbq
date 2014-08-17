t2fbq
=====

File Format
-----------

Byte order is little endian and the character encoding of file names seems to
be ASCII (or ISO-8859-1/UTF-8 that coincidentally only uses ASCII compatiple
characters).

### File Header

	Offset  Size  Type      Description
	     0     4  uint32_t  version (2)
	     4     4  uint32_t  number of entries
	     8     4  uint32_t  size of index

### Index Record

	Offset  Size  Type      Description
         0     N  char[N]   null terminated absolute file name ('/' is path separator)
         N     4  uint32_t  data offset relative to end of index
	   N+4     5  ?         ?
	   N+9     4  uint32_t  data size
	  N+13     4  ?         ?
