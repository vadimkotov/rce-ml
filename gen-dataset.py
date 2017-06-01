import sys
import csv
import logging


from core import database
from core import utils

from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError
from elftools.elf.sections import SymbolTableSection


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger()



class SOFunction:
    def __init__(self, name, virtual_address, size, bytes_):
        self.name = name
        self.virtual_address = virtual_address
        self.size = size
        self.bytes = bytes_


class File:
    def __init__(self, path, size, bitness):
        self.path = path
        self.size = int(size)
        self.bitness = int(bitness)
        self.sha256 = utils.get_sha256(path)

        
class SOParserError(Exception):pass

class SOParser:
    def __init__(self, path):

        self.__elffile = None
        
        try:
            stream = open(path, 'rb')
        except IOError as e:
            logger.error(str(e))
        
        try:
            self.__elffile = ELFFile(stream)
        except ELFError as e:
            raise SOParserError(str(e))
        except IOError as e:
            raise SOParserError(str(e))            

    
    def find_symbol_table(self):
        sym_section = self.__elffile.get_section_by_name('.symtab')
    
        if not sym_section:
            sym_section = self.__elffile.get_section_by_name('.dynsym')
        
            if not sym_section:
                raise SOParserError("No symbol table")            

    
        if isinstance(sym_section, SymbolTableSection):
            return sym_section
        else:
            raise SOParserError("Section found is not Symbol Table")


    def get_section(self, idx):
        return self.__elffile.get_section(idx)

    def functions_iter(self):
        sym_section = self.find_symbol_table()
        
        for sym in sym_section.iter_symbols():
            
            name = sym.name
        
            if sym.entry.st_info.type != 'STT_FUNC':
                continue

            size = sym.entry.st_size

            if not size:
                continue

            section = self.get_section(sym.entry.st_shndx)

            data = section.data()
        
            virtual_address = sym.entry.st_value
            section_offset = section.header.sh_offset

            offset = virtual_address - section_offset
            bytes_ = utils.compress(data[offset:offset + size])

            yield SOFunction(name, virtual_address, size, bytes_)
    

def process_so(file, db):
    try:
        so_parser = SOParser(file.path)
    except SOParserError as e:
        logger.error(e)
        return


    file_id = db.add_file_info(file)
    db.commit()
    
    try:
        for func in so_parser.functions_iter():
            db.add_func_info(file_id, func)
        
    except SOParserError as e:
        logger.error(e)
        return

    db.commit()
            

def main():
    if len(sys.argv) != 3:
        print 'Usage: %s <csv with files> <database>' % sys.argv[0]
        sys.exit()

    fd = open(sys.argv[1])
    reader = csv.reader(fd)

    db = database.Database(sys.argv[2])
    db.create_tables()
    db.commit()

    
    # Skip the headers
    reader.next()
    
    for row in reader:
        path = row[0]
        logger.info('Checking %s' % path)
        
        process_so(File(row[0], row[1], row[2]), db)

    fd.close()


        
if __name__ == '__main__':
    main()
