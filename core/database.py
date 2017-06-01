import sqlite3

def dict_factory(cursor, row):
    d = {}
    for idx,col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


def store_binary(buf):
    if not buf:
        return ''
    else:
        return sqlite3.Binary(buf.read())

class Database:
    def __init__(self, filename):
        self.__conn = sqlite3.connect(filename)
        self.__conn.row_factory = dict_factory
        self.__cursor = self.__conn.cursor()
        
    def commit(self):
        self.__conn.commit()

    def close(self):
        self.__cursor.close()
        self.__conn.close()

    def create_tables(self):
        self.__cursor.execute("""
        CREATE TABLE IF NOT EXISTS files (
            sha256 TEXT UNIQUE,
            path TEXT,
            size INT,
            bitness INT
        )""")

        self.__cursor.execute("""
        CREATE TABLE IF NOT EXISTS functions (
            sha256 TEXT UNIQUE,
            file_id INTEGER,
            virtual_address INTEGER,
            name TEXT,
            size INTEGER,
            bytes BLOB
        )""")

        self.commit()

    def add_file_info(self, file):

        self.__cursor.execute("""
        SELECT rowid FROM files WHERE sha256 = ?
        """, (file.sha256,))

        res = self.__cursor.fetchone()

        if res:
            return res['rowid']
        
        self.__cursor.execute("""
        INSERT INTO files ( sha256, path, size, bitness )
        VALUES (?, ?, ?, ?)
        """, (file.sha256, file.path, file.size, file.bitness))

        return self.__cursor.lastrowid


    def add_func_info(self, file_id, func):

        self.__cursor.execute("""
        SELECT rowid FROM functions 
        WHERE
        file_id = ? AND
        virtual_address = ?
        """, (file_id, func.virtual_address))

        res = self.__cursor.fetchone()

        if res:
            return
        
        self.__cursor.execute("""
        INSERT INTO functions (file_id, virtual_address, name, size, bytes)
        VALUES (?, ?, ?, ?, ?)
        """, (file_id, func.virtual_address, func.name, func.size, sqlite3.Binary(func.bytes.read())))

        
    def get_random_functions(self, limit):
        self.__cursor.execute("""
        SELECT rowid,* FROM functions 
        ORDER BY RANDOM()
        LIMIT %d
        """ % limit)

        return self.__cursor.fetchall()


    def get_random_functions_by_file_id(self, file_id, limit):
        self.__cursor.execute("""
        SELECT rowid,* FROM functions WHERE file_id = ?
        ORDER BY RANDOM()
        LIMIT %d
        """ % limit, (file_id,))

        return self.__cursor.fetchall()

    
    def get_file_by_sha256(self, sha256):
        self.__cursor.execute("""
        SELECT rowid,* FROM files
        WHERE sha256 = ?
        """, (sha256,))
        return self.__cursor.fetchone()
        
    
    def get_file_by_id(self, file_id):
        self.__cursor.execute("""
        SELECT * FROM files
        WHERE rowid = ?
        """, (file_id,))
        return self.__cursor.fetchone()

    def get_functions_by_file_id(self, file_id):
        self.__cursor.execute("""
        SELECT * FROM functions
        WHERE 
        file_id = ?
        """, (file_id,))

        return self.__cursor.fetchall()

    def get_number_of_rows(self, table):
        self.__cursor.execute("""
        SELECT COUNT(*) as total
        FROM %s""" % table)

        return self.__cursor.fetchone()['total']

    def get_functions(self, offset, limit):
        self.__cursor.execute("""
        SELECT rowid,* FROM functions 
        LIMIT %d OFFSET %d""" % (limit, offset))
        return self.__cursor.fetchall()

    def get_function_by_id(self, id_):
        self.__cursor.execute("""
        SELECT rowid,* FROM functions
        WHERE rowid = ?
        """, (id_,))
        return self.__cursor.fetchone()
        
    def delete_function(self, rowid):
        self.__cursor.execute("""
        DELETE FROM functions
        WHERE rowid = ?""", (rowid,))

        
