import sys
import random
import struct

import matplotlib.pyplot as plt

from sklearn.cluster import KMeans
from sklearn.decomposition import PCA

from core import database
from core import utils
from core import disassembler
from core import bag

import numpy as np



SAMPLE_SIZE = 1000

def get_distribution1(bytes_):
    
    distr = [0] * 256
    
    for b in bytearray(bytes_):
        distr[b] += 1

    return np.array(distr) / float(256)


def get_distribution2(bytes_):

    bytes_ = bytearray(bytes_)
    
    distr = [0] * 256

    if not bytes_:
        return distr
    
    for i in xrange(0, len(bytes_) - 1):
        distr[bytes_[i]] += 1
        b = (bytes_[i] >> 4) | (bytes_[i+1] & 0xF0)
        distr[b] += 1

    distr[bytes_[-1]] += 1

    return np.array(distr) / float(256)


def get_distribution3(bytes_):
    
    distr = [0] * 65536
    
    for i in xrange(0, len(bytes_)-1):
        b = struct.unpack('<H', bytes_[i:i+2])[0]
        distr[b] += 1

    return np.array(distr) / float(65536)


import capstone

OP_TYPES = {
    capstone.x86.X86_OP_IMM: 'imm',
    capstone.x86.X86_OP_MEM: 'mem',
    capstone.x86.X86_OP_REG: 'reg'
}




def mnem_op_type_repr(instr):
    op_types = []
    
    for operand in instr.operands:
        op_types.append(OP_TYPES[operand.type])

    return instr.mnemonic + ' ' + ','.join(op_types)


def get_distribution4(bytes_):
    distr_ = [0] * len(bag.MNEM_OP_TYPES)
    
    d = disassembler.Disassembler(bytes_, 0)
    d.disassemble()

    for instr in d.instr_iter():
        r = mnem_op_type_repr(instr)
        try:
            idx = bag.MNEM_OP_TYPES.index(r)
        except ValueError as e:
            continue

        distr_[idx] += 1

    return np.array(distr_) / float(len(bag.MNEM_OP_TYPES))


def has_calls(bytes_):
    d = disassembler.Disassembler(bytes_, 0)
    d.disassemble()
    
    for instr in d.instr_iter():
        if instr.mnemonic == 'call':
            return True

    return False

def main():
    if len(sys.argv) != 2:
        print 'Usage: %s <sqlite>' % sys.argv[0]
        sys.exit()
        
    db = database.Database(sys.argv[1])
    sample = db.get_random_functions(SAMPLE_SIZE)

    X = []

    cnt = 0

    for func in sample:
        bytes_ = utils.decompress(func['bytes'])
        
        if has_calls(bytes_):
            continue
        

        x = get_distribution1(bytes_)

        X.append(x[1:-1])
        cnt += 1


    print cnt
    
    pca = PCA(n_components=2)
    pca.fit(X)

    X_pca = pca.transform(X)

    plt.scatter(X_pca[:,0], X_pca[:,1])

    plt.show()

    
if __name__ == '__main__':
    main()
