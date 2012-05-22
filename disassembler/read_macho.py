from utils import num_lsb, num_msb

class Size:
    pass

Size.uint32_t = 4
Size.cpu_type_t = 4
Size.cpu_subtype_t = 4

class MachO:
    pass

MachO.magic_number_host_32 = 0xfeedface
MachO.magic_number_opposite_32 = 0xcefaedfe 
MachO.magic_number_host_64 = 0xfeedfacf
MachO.magic_number_opposite_64 = 0xcffaedfe

MachO.cpu_arch_abi64 = 0x01000000 

MachO.cpu_type_any = (1<<Size.cpu_type_t) - 1
MachO.cpu_type_vax = 1
MachO.cpu_type_mc680x0 = 6
MachO.cpu_type_x86 = 7
MachO.cpu_type_i386 = MachO.cpu_type_x86
MachO.cpu_type_x86_64 = MachO.cpu_type_x86 | MachO.cpu_arch_abi64
MachO.cpu_type_mc98000 = 10
MachO.cpu_type_hppa = 11
MachO.cpu_type_arm = 12
MachO.cpu_type_mc88000 = 13
MachO.cpu_type_sparc = 14
MachO.cpu_type_i860 = 15
MachO.cpu_type_alpha = 16
MachO.cpu_type_powerpc = 18
MachO.cpu_type_powerpc64 = MachO.cpu_type_powerpc | MachO.cpu_arch_abi64

class Filetype:
    pass

Filetype.object = 0x1
Filetype.execute = 0x2
Filetype.fixed_vm_shared_library = 0x3
Filetype.core = 0x4
Filetype.preloaded_executable = 0x5
Filetype.dynamic_library = 0x6
Filetype.dynamic_link_editor = 0x7
Filetype.dynamic_bundle = 0x8
Filetype.shared_library_stub = 0x9
Filetype.debug_only = 0xa

class MachoException(Exception):
    def __init__(self, str):
        Exception.__init__(self, str)

class NotMacho(MachoException):
    def __init__(self, str):
        MachoException.__init__(self, str)

def verifyMagic(magic):
    # return same/opposite as whatever was used to read the magic number
    if magic == MachO.magic_number_host_32:
        return num_lsb
    if magic == MachO.magic_number_opposite_32:
        return num_msb
    raise NotMacho("invalid macho-o magic number")

def cpuType(type):
    if type == MachO.cpu_type_any:
        return "Any"
    if type == MachO.cpu_type_vax:
        return "VAX"
    if type == MachO.cpu_type_mc680x0:
        return "mc680x0"
    if type == MachO.cpu_type_x86:
        return "x86"
    if type == MachO.cpu_type_i386:
        return "i386"
    if type == MachO.cpu_type_x86_64:
        return "64"
    if type == MachO.cpu_type_mc98000:
        return "mc98000"
    if type == MachO.cpu_type_hppa:
        return "hppa"
    if type == MachO.cpu_type_arm:
        return "arm"
    if type == MachO.cpu_type_mc88000:
        return "mc88000"
    if type == MachO.cpu_type_sparc:
        return "sparc"
    if type == MachO.cpu_type_i860:
        return "i860"
    if type == MachO.cpu_type_alpha:
        return "alpha"
    if type == MachO.cpu_type_powerpc:
        return "powerpc"
    if type == MachO.cpu_type_powerpc64:
        return "powerpc64"
    raise MachoException("unknown cpu type %d" % type)

def fileType(type):
    if type == Filetype.object:
        return "Relocatable object file"
    if type == Filetype.execute:
        return "Demand paged executable file"
    if type == Filetype.fixed_vm_shared_library:
        return "Fixed VM shared library file "
    if type == Filetype.core:
        return "Core file"
    if type == Filetype.preloaded_executable:
        return "Preloaded executable file"
    if type == Filetype.dynamic_library:
        return "Dynamically bound shared library"
    if type == Filetype.dynamic_link_editor:
        return "Dynamic link editor"
    if type == Filetype.dynamic_bundle:
        return "Dynamically bound bundle file"
    if type == Filetype.shared_library_stub:
        return "shared library stub for static linking only, no section contents"
    if type == Filetype.debug_only:
        return "Companion file with only debug sections"
    raise MachoException("unknown file type %d" % type)

def read32(file):
    magic = num_lsb(file.read(Size.uint32_t))
    # print "Magic is %x" % magic
    nummer = verifyMagic(magic)
    print "Detected Mach-O file"
    cputype = nummer(file.read(Size.cpu_type_t))
    print "Cpu type is " + cpuType(cputype)
    cpusubtype = nummer(file.read(Size.cpu_subtype_t))
    filetype = nummer(file.read(Size.uint32_t))
    print "File type is " + fileType(filetype)
    ncmds = nummer(file.read(Size.uint32_t))
    sizeofcmds = nummer(file.read(Size.uint32_t))
    flags = nummer(file.read(Size.uint32_t))

def read(file):
    read32(file)
