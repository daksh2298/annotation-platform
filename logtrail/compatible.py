import sys

if sys.version_info[0] == 3:
    uchr = chr
elif sys.version_info[0] == 2:
    uchr = unichr
