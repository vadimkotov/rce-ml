import capstone
import networkx as nx


# Groups of mnemonics that we use
CJUMPS = ['je', 'jne', 'jg', 'jge',
          'ja', 'jae', 'jl', 'jle',
          'jb', 'jbe', 'jo', 'jno',
          'jz', 'jnz', 'js', 'jns', 'jp']


    
class DisassemblerError(Exception): pass

class Disassembler(object):
    def __init__(self, bytes_, start_addr, mode = capstone.CS_MODE_64):
        self.__md = capstone.Cs(capstone.CS_ARCH_X86, mode)
        self.__md.detail = True

        # Address - instruction
        self.__map = {}

        # List of visited addresses
        self.__visited = []
        
        self.bytes = bytes_
        self.function_start = start_addr
        self.function_end = start_addr + len(bytes_) - 1

        # Dictionary of basic blocks of a function
        # keys are addresses and values are lists
        # of addresses, look'em up in __map.
        self.basic_blocks = {}

        # Addresses of basic block that end with RET
        self.exit_blocks = []

        # Instance of nx.Digraph to represent the
        # CFG
        self.graph = nx.DiGraph()

        self.longest_path = None
        self.shortest_path = None

    def get_md(self):
        return self.__md

    def get_instr_at_addr(self, addr):
        return self.__map.get(addr, None)

    def disassemble(self):
        # This function builds the map of diassembled
        # instructions and also generates the nodes 
        # for the CFG

        # Root node always starts with first address
        self.add_node(self.function_start)

        
        for instr in self.__md.disasm(self.bytes, self.function_start):
            self.__map[instr.address] = instr

            mnemonic = instr.mnemonic
            next_address = instr.address + instr.size

            if mnemonic in CJUMPS or mnemonic == 'jmp':
                op = instr.operands[0]
                
                if op.type == capstone.x86.X86_OP_IMM:
                    jmp_target = op.imm

                    # Let's ingnore jmp tables and tail calls
                    # for now
                    if jmp_target >= self.function_start  and\
                       jmp_target <= self.function_end:
                        self.add_node(jmp_target)
                        
                    self.add_node(next_address)


    def print_disassembly(self):
        for addr, instr in sorted(self.__map.iteritems(), key = lambda x: x[0]):
            print '%.8x %s %s' % (addr, instr.mnemonic, instr.op_str)

    def instr_iter(self):
        for addr, instr in sorted(self.__map.iteritems(), key = lambda x: x[0]):
            yield instr
            
    ###### CFG related methods
    def add_node(self, address):
        if address in self.graph.node:
            return

        self.graph.add_node(address)
        self.basic_blocks[address] = []

    def add_edge(self, from_, to_):
        self.graph.add_edge(from_, to_)
        
    def build_cfg(self):
        self.traverse(self.function_start)
        self.find_remaining_exit_blocks()
        
    def find_remaining_exit_blocks(self):
        # Add any exit blocks without return
        # e.g. tail calls
        have_outgoing_edge = [from_ for from_, _ in self.graph.edges()]
        
        for node in self.graph.nodes():
            if node not in have_outgoing_edge:
                self.exit_blocks.append(node)
        
    def get_blocks_ordered(self):
        return [addr for addr in sorted(self.basic_blocks)]
    
    def get_paths(self):
        # If there's only one node
        if nx.number_of_nodes(self.graph) == 1:
            self.shortest_path = self.longest_path = [self.function_start]
            return [[self.function_start]]

        # If there aren't any obvious exit blocks
        if len(self.exit_blocks) == 0:
            return
                
        # We need to go through all the possible paths from
        # function start to each of exit blocks
        all_paths = []
        
        longest_path_len = 0
        shortest_path_len = None
        
        for ret in self.exit_blocks:
            paths = (nx.all_simple_paths(self.graph, source = self.function_start, target = ret))
            
            for path in paths:
                if len(path) > longest_path_len:
                    longest_path_len = len(path)
                    self.longest_path = path

                if not shortest_path_len or len(path) < shortest_path_len:
                    shortest_path_len = len(path)
                    self.shortest_path = path
                    
            all_paths.extend(paths)
            
        return all_paths
            
    def traverse(self, address):

        block_address = address
        
        while address < self.function_end:

            """
            TODO: debug this issue
            """
            if address not in self.__map:
                return
            
            instr = self.__map[address]
            
            if address in self.__visited:
                return

            self.__visited.append(address)

            mnemonic = instr.mnemonic
            next_address = address + instr.size

            self.basic_blocks[block_address].append(address)

            # Check if it's an exit block
            if mnemonic.startswith('ret'):
                self.exit_blocks.append(block_address)
                return

            elif mnemonic in CJUMPS or mnemonic == 'jmp':
                op = instr.operands[0]

                if op.type == capstone.x86.X86_OP_IMM:
                    jmp_target = op.imm

                    if jmp_target >= self.function_start and \
                       jmp_target <= self.function_end:
                        self.traverse(jmp_target)
                        self.add_edge(block_address, jmp_target)
                    
                    self.traverse(next_address)
                    self.add_edge(block_address, next_address)

                    return
            else:
                if next_address in self.graph.node:
                    self.traverse(next_address)
                    self.add_edge(block_address, next_address)
                    return
                        
            address = next_address

    ##### END CFG related methods
        
    
