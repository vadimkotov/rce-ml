import sys
import os

from core import disassembler
from core import database
from core import utils

import matplotlib.gridspec as gridspec
import matplotlib.pyplot as plt
import numpy as np

import capstone


SAMPLE_SIZE = 1000
SAMPLE_MIN_SIZE = 50
TOP = 30
N = 1


MNEM_SHIFT = ['shl', 'shr', 'sar', 'sal', 'ror', 'rol']
MNEM_ADD_INT = ['adc', 'inc', 'add']
MNEM_ADD_FP = ['addsd', 'addss', 'addpd', 'addps', 'paddd', 'faddp', 'fadd', 'fiadd']
MNEM_SUB_INT = ['sbb', 'dec', 'sub'] 
MNEM_SUB_FP = ['subsd', 'subss', 'subpd', 'subps', 'fsub', 'fsubrp', 'fsubp', 'fsubr']
MNEM_MUL_INT = ['imul', 'mul']
MNEM_MUL_FP = ['fmul', 'mulsd', 'mulss', 'mulpd', 'mulps', 'fmulp']
MNEM_DIV_INT = ['div', 'idiv']
MNEM_DIV_FP = ['divsd', 'divss', 'divpd', 'fdiv', 'fdivr', 'fdivrp', 'fidivr']
MNEM_LOGIC = ['and', 'or']
MNEM_LOGIC_FP = ['andpd', 'andps', 'andnpd', 'andnps', 'orpd', 'orps']
MNEM_XOR = ['xor']
MNEM_XOR_FP = ['pxor', 'xorpd', 'xorps']

RET_TYPES = ['ret', 'retn', 'retf']

PUSH_TYPES = ['push', 'pushfq']
POP_TYPES = ['pop', 'popfq']

CMP_TYPES = [
    'cmp', 'cmplesd', 'cmpltss', 'cmpxchg', 'cmpltsd', 'cmpnltsd', 'cmpsb', 
    'cmpsd', 'cmpnltss', 'cmplepd', 'cmpnlesd', 'cmpltpd', 'cmpunordsd',
    'cmpnless'
]


MOV_TYPES = [
    'mov', 'movsd', 'movzx', 'movsxd', 'movss', 'movapd', 'movaps',
    'movabs', 'movsx', 'cmove', 'cmovne', 'movups', 'movupd',
    'cmovbe', 'movdqa', 'cmovs', 'cmovle', 'cmova', 'cmovg',
    'cmovge', 'cmovb', 'cmovl', 'cmovns', 'cmovae', 'movq',
    'movdqu', 'movd', 'movsb', 'movhlps', 'fcmove', 'fcmovnbe',
    'fcmovbe', 'movlhps', 'movhpd', 'movmskpd'
]


OTHER = ['test', 'jmp', 'call', 'leave', 'nop', 'lea']

NOISE = []
NOISE.extend(RET_TYPES)
NOISE.extend(PUSH_TYPES)
NOISE.extend(POP_TYPES)
NOISE.extend(CMP_TYPES)
NOISE.extend(MOV_TYPES)
NOISE.extend(OTHER)

# NOISE = ['mov', 'nop', 'test', 'cmp', 'pop', 'push', 'call', 'ret', 'lea', 'jmp']        


ABST_TABLE = {
    'shift': MNEM_SHIFT,
    'add': MNEM_ADD_INT,
    'fadd': MNEM_ADD_FP,
    'sub': MNEM_SUB_INT,
    'fsub': MNEM_SUB_FP,
    'mul': MNEM_MUL_INT,
    'fmul': MNEM_MUL_FP,
    'div': MNEM_DIV_INT,
    'fdiv': MNEM_DIV_FP,
    'logic': MNEM_LOGIC,
    'flogic': MNEM_LOGIC_FP,
    'fxor': MNEM_XOR_FP
}



OP_TYPES = {
    capstone.x86.X86_OP_IMM: 'imm',
    capstone.x86.X86_OP_MEM: 'mem',
    capstone.x86.X86_OP_REG: 'reg'
}


def r_mnem_op_types(instr):

    if instr.mnemonic == 'nop':
        return 'nop'
    
    op_types = []
    
    for operand in instr.operands:
        op_types.append(OP_TYPES[operand.type])

    return (instr.mnemonic + ' ' + ','.join(op_types)).strip()


class FakeInstr:
    def __init__(self, mnemonic, operands):
        self.mnemonic = mnemonic
        self.operands = operands


def ops_same(op_str):
    op1, op2 = op_str.split(', ')
    return op1 == op2



def abstract_instr(instr):
    mnem_split = instr.mnemonic.split(' ')

    if len(mnem_split) == 1:
        mnem = mnem_split[0].strip()
    else:
        mnem = mnem_split[1].strip()
          
    if mnem in NOISE:
        return

    if mnem == 'xor':
        if ops_same(instr.op_str):
            return

    if mnem in MNEM_XOR_FP:
        if ops_same(instr.op_str):
            return

    if mnem in disassembler.CJUMPS:
        # instr = FakeInstr('cjump', instr.operands)
        return

    for op_name, list_ in ABST_TABLE.iteritems():
        if mnem in list_:
            return op_name
        
    return mnem


def extract(sample):
    stat = {}
    
    for func in sample:
        
        bytes_ = utils.decompress(func['bytes'])

    
        d = disassembler.Disassembler(bytes_, 0)
        d.disassemble()

    
        istream = []

        for instr in d.instr_iter():
            abstr_instr = abstract_instr(instr)

            if abstr_instr:
                istream.append(abstr_instr)
            
        

        for i in xrange(len(istream) - N + 1):
            ngram = '/'.join([istream[i+j] for j in range(N) ])

            if ngram not in stat:
                stat[ngram] = 0

            stat[ngram] += 1

    return stat


def plot_stat(stat, ax, title = ''):

    ind = np.arange(TOP)
    width = 30
    
    y = []
    labels = []
    
    total = float(sum(stat.values()))

    for ngram, cnt in sorted(stat.iteritems(), key=lambda x:x[1], reverse = True)[:TOP]:
        y.append(cnt / total)
        labels.append(ngram)

    print title, len(y)
    
    if len(y) < TOP:
        delta = TOP - len(y)
        y.extend([0] * delta)
        labels.extend([''] * delta)

        
    y.reverse()
    labels.reverse()

    # print len(y)
    
    rects = ax.barh(ind * width, y, width, color = '#c0c0c0')

    ax.set_yticks((ind * width) + width/2)
    ax.set_yticklabels(labels)#, x = .8)
    
    ax.set_title(title)

    return max(y)

        
def main():
    if len(sys.argv) != 4:
        print 'Usage: %s <sqlite> <file_id1> <file_id2>' % sys.argv[0]
        sys.exit()

    db = database.Database(sys.argv[1])

    file_id1 = sys.argv[2]
    file_id2 = sys.argv[3]
    
    sample1 = db.get_random_functions_by_file_id(file_id1, SAMPLE_SIZE)
    sample2 = db.get_random_functions_by_file_id(file_id2, SAMPLE_SIZE)

    len1 = len(sample1)
    len2 = len(sample2)

    if len1 < SAMPLE_MIN_SIZE:
        print 'Sample 1 is too small:', len1
        return

    if len2 < SAMPLE_MIN_SIZE:
        print 'Sample 2 is too small:', len2
        return
    
    if len1 < len2:
        sample2 = sample2[:len1]
    elif len2 < len1:
        sample1 = sample1[:len2]

    print len(sample1), len(sample2)

    stat1 = extract(sample1)
    file_name_1 = os.path.basename(db.get_file_by_id(file_id1)['path'])

    
    stat2 = extract(sample2)
    file_name_2 = os.path.basename(db.get_file_by_id(file_id2)['path'])

    # print len(stat1), len(stat2)
    
    f, axarr = plt.subplots(1, 2, sharex=False)


    xmax1 = plot_stat(stat1, axarr[0], file_name_1)
    xmax2 = plot_stat(stat2, axarr[1], file_name_2)

    xlim = 0.5
    
    axarr[0].set_xlim((0,xlim))
    axarr[1].set_xlim((0,xlim))
    
    plt.show()

    
if __name__ == '__main__':
    main()
