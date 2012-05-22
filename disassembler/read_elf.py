from utils import num_msb, num_lsb

class ElfException(Exception):
    def __init__(self, str):
        Exception.__init__(self, str)

class NotElf(ElfException):
    def __init__(self, str):
        ElfException.__init__(self, str)

addr_size = 4
half_size = 2
off_size = 4
sword_size = 4
word_size = 4

class ObjectType:
    def __init__(self, value, name):
        self.value = value
        self.name = name

    def __str__(self):
        return self.name

    class Convert:
        def __call__(self, value):
            for obj in [ObjectType.NONE, ObjectType.REL, ObjectType.EXEC, ObjectType.DYN, ObjectType.CORE]:
                if obj.value == value:
                    return obj
            raise ElfException("Unknown type value '" + str(value) + "'")
    convert = Convert()

ObjectType.NONE = ObjectType(0, "None")
ObjectType.REL = ObjectType(1, "Relocatable")
ObjectType.EXEC = ObjectType(2, "Executable")
ObjectType.DYN = ObjectType(3, "Shared object")
ObjectType.CORE = ObjectType(4, "Core file")
ObjectType.LOPROC = ObjectType(0xff00, "Processor specific")
# and values in between
ObjectType.HIPROC = ObjectType(0xffff, "Processor specific")

class Machine:
    def __init__(self, value, name):
        self.value = value
        self.name = name

    def __str__(self):
        return self.name

    class Convert:
        def __call__(self, value):
            for obj in [Machine.NONE, Machine.M32, Machine.SPARC, Machine._386, Machine._68K, Machine._88K, Machine._86Q, Machine.MIPS]:
                if obj.value == value:
                    return obj
            raise ElfException("Unknown type value '" + str(value) + "'")
    convert = Convert()

Machine.NONE = Machine(0, "No machine")
Machine.M32 = Machine(1, "AT&T WE 32100")
Machine.SPARC = Machine(2, "SPARC")
Machine._386 = Machine(3, "Intel 80386")
Machine._68K = Machine(4, "Motorola 68000")
Machine._88K = Machine(5, "Motorola 88000")
Machine._86Q = Machine(7, "Intel 80860")
Machine.MIPS = Machine(8, "MIPS RS3000")

def numxx(stuff):
    return ord(stuff[0]) + ord(stuff[1]) * 256

def verifyMagic(data):
    if not (ord(data[0]) == 0x7f and \
            data[1] == 'E' and \
            data[2] == 'L' and \
            data[3] == 'F'):
        raise NotElf("Not and ELF file!")

def byteOrder(num):
    if num == 1:
        return num_lsb
    elif num == 2:
        return num_msb
    else:
        raise ElfException("Invalid value for byte order " + str(num))

class Section:
    def __init__(self, sh_name, sh_type, sh_flags, sh_addr, sh_offset, 
                       sh_size, sh_link, sh_info, sh_addralign, sh_entsize,
                       name, index):
        self.sh_name = sh_name
        self.sh_type = sh_type
        self.sh_flags = sh_flags
        self.sh_addr = sh_addr
        self.sh_offset = sh_offset
        self.sh_size = sh_size
        self.sh_link = sh_link
        self.sh_info = sh_info
        self.sh_addralign = sh_addralign
        self.sh_entsize = sh_entsize
        self.name = name
        self.index = index

def read_sections(file, offset, entry_size, entries, convert, strings):
    file.seek(offset)
    for i in range(0,entries):
        stuff = file.read(entry_size)
        index = [0]
        def get(n):
            all = stuff[index[0]:index[0]+n]
            index[0] += n
            return convert(all)

        def getString(string_index):
            str = ""
            while ord(strings[string_index]) != 0:
                str += strings[string_index]
                string_index += 1
            return str

        sh_name = get(word_size)
        sh_type = get(word_size)
        sh_flags = get(word_size)
        sh_addr = get(addr_size)
        sh_offset = get(off_size)
        sh_size = get(word_size)
        sh_link = get(word_size)
        sh_info = get(word_size)
        sh_addralign = get(word_size)
        sh_entsize = get(word_size)

        # print "Section[%d] name (%d) is '%s'" % (i, sh_name, getString(sh_name))
        yield Section(sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
                      sh_link, sh_info, sh_addralign, sh_entsize, getString(sh_name), i)


def read_string_section(file, offset, entry_size, convert, string_index):
    file.seek(offset + entry_size * string_index)
    stuff = file.read(entry_size)
    index = [0]
    def get(n):
        all = stuff[index[0]:index[0]+n]
        index[0] += n
        return convert(all)

    sh_name = get(word_size)
    sh_type = get(word_size)
    sh_flags = get(word_size)
    sh_addr = get(addr_size)
    sh_offset = get(off_size)
    sh_size = get(word_size)
    sh_link = get(word_size)
    sh_info = get(word_size)
    sh_addralign = get(word_size)
    sh_entsize = get(word_size)

    file.seek(sh_offset)
    return file.read(sh_size)

class X86Instruction:
    def __init__(self, file):
        self.opcode = ord(file.read(1))
        self.length = 1

    # The raw bytes that make up this instruction
    def raw(self):
        return [self.opcode]

    # The canonical string of this instruction
    def __str__(self):
        if self.opcode == 0x31:
            return 'xor'
        return '?'

def disassemble(file, offset, size):
    file.seek(offset)
    while size > 0:
        instruction = X86Instruction(file)
        size -= instruction.length
        print "%s: %s" % (' '.join([hex(n) for n in instruction.raw()]), instruction)

def read_header(file):
    # contains magic bytes and other important information
    identifier = file.read(16)
    verifyMagic(identifier[0:4])
    print "Detected ELF"
    # 32 or 64bit
    ei_class = ord(identifier[4])
    # msb or lsb
    ei_data = ord(identifier[5])
    # current or something else
    ei_version = ord(identifier[6])
    # padding bytes
    ei_pad = identifier[7]
    numer = byteOrder(ei_data)

    # file type (executable, shared object, etc)
    type = numer(file.read(half_size))
    # x86, motorola, etc
    machine = numer(file.read(half_size))
    # current
    version = numer(file.read(word_size))
    # first address control is given to when the binary is executed
    entry = numer(file.read(addr_size))
    # header table offset
    phoff = numer(file.read(off_size))
    # section table offset
    shoff = numer(file.read(off_size))
    # machine dependent flags
    flags = numer(file.read(word_size))
    # elf header size in bytes
    ehsize = numer(file.read(half_size))
    # size of one entry in the header table
    phentsize = numer(file.read(half_size))
    # number of entries in the header
    phnum = numer(file.read(half_size))
    # section header entry size in bytes
    shentsize = numer(file.read(half_size))
    # number of section entries
    shnum = numer(file.read(half_size))
    # section index that holds the string table
    shstrndx = numer(file.read(half_size))

    print "File is " + str(ObjectType.convert(type))
    print "Machine is " + str(Machine.convert(machine))
    print "Version is " + str(version)
    print "Entry is " + str(hex(entry))
    print "Header size is " + str(ehsize)
    print "String index is " + str(shstrndx)

    string_section = read_string_section(file, shoff, shentsize, numer, shstrndx)

    for section in read_sections(file, shoff, shentsize, shnum, numer, string_section):
        # print "Section(%d) is %s" % (section.index, section.name)
        if section.name == ".text":
            disassemble(file, section.sh_offset, section.sh_size)

def read(file):
    read_header(file)
