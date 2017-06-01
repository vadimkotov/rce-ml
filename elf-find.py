"""
This program goes through the computer's file system
and collects all the paths of ELF shared libraries and
shared libraries
"""

import sys
import os
import re

from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError

EXCLUDED_DIRS = re.compile(r'/home/|/mnt/|/opt/|/rw/')

# ELF e_type:
# shared library
ET_DYN = 'ET_DYN'
# exectuable
ET_EXEC = 'ET_EXEC'
# relocatable (object file)
ET_REL = 'ET_REL'


def open_elf(path):
    try:
        fd = open(path, 'rb')
    except IOError as e:
        return
    
    try:
        elf = ELFFile(fd)
    except ELFError as e:
        return
    except IOError as e:
        return
        
    fd.close()
    return elf

def main():

    if len(sys.argv) != 2:
        print 'Usage: %s <root>' % sys.argv[0]
        sys.exit()

    path = sys.argv[1]
    
    print 'path,size,bitness,e_type'
    
    for root, dirs, files in os.walk(path):
        
        if EXCLUDED_DIRS.match(root):
            continue
        
        for filename in files:
            path = os.path.join(root, filename)

            # Do not follow symlinks
            if os.path.islink(path):
                continue
            
            elf = open_elf(path)

            if elf:
                e_type = elf.header.e_type

                # We're only interested in libraries
                if e_type != ET_DYN:
                    continue
                
                size = os.path.getsize(path)
                bitness = elf.elfclass
                
                print '%s,%d,%d,%s' % (path, size, bitness, e_type)
            

if __name__ == '__main__':
    main()
