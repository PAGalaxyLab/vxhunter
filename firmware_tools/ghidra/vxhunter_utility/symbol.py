# coding=utf-8
from ghidra.program.model.util import CodeUnitInsertionException
from ghidra.program.model.data import (
    CharDataType,
    UnsignedIntegerDataType,
    IntegerDataType,
    ShortDataType,
    PointerDataType,
    VoidDataType,
    ByteDataType,
    ArrayDataType,
    StructureDataType,
    EnumDataType
)
from ghidra.program.model.symbol import RefType, SourceType
from common import *


# The Python module that Ghidra directly launches is always called __main__.  If we import
# everything from that module, this module will behave as if Ghidra directly launched it.
from __main__ import *


function_name_key_words = ['bzero', 'usrInit', 'bfill']

need_create_function = [
    0x04,
    0x05
]

# tp_link_symbol_map = ['']

vx_5_symbol_type_enum = {
    0x00: "Undefined Symbol",
    0x01: "Global (external)",
    0x02: "Local Absolute",
    0x03: "Global Absolute",
    0x04: "Local .text",
    0x05: "Global .text",
    0x06: "Local Data",
    0x07: "Global Data",
    0x08: "Local BSS",
    0x09: "Global BSS",
    0x12: "Local Common symbol",
    0x13: "Global Common symbol",
    0x40: "Local Symbols related to a PowerPC SDA section",
    0x41: "Global Symbols related to a PowerPC SDA section",
    0x80: "Local symbols related to a PowerPC SDA2 section",
    0x81: "Global symbols related to a PowerPC SDA2 section"
}

vx_6_symbol_type_enum = {
    0x00: "Undefined Symbol",
    0x01: "Global (external)",
    0x02: "Local Absolute",
    0x03: "Global Absolute",
    0x04: "Local .text",
    0x05: "Global .text",
    0x08: "Local Data",
    0x09: "Global Data",
    0x10: "Local BSS",
    0x11: "Global BSS",
    0x20: "Local Common symbol",
    0x21: "Global Common symbol",
    0x40: "Local Symbols",
    0x41: "Global Symbols"
}

# Init data type
ptr_data_type = PointerDataType()
byte_data_type = ByteDataType()
char_data_type = CharDataType()
void_data_type = VoidDataType()
unsigned_int_type = UnsignedIntegerDataType()
short_data_type = ShortDataType()
char_ptr_type = ptr_data_type.getPointer(char_data_type, 4)
void_ptr_type = ptr_data_type.getPointer(void_data_type, 4)
# Prepare VxWorks symbol types
vx_5_sym_enum = EnumDataType("Vx5symType", 1)
for flag in vx_5_symbol_type_enum:
    vx_5_sym_enum.add(vx_5_symbol_type_enum[flag], flag)
vx_6_sym_enum = EnumDataType("Vx6symType", 1)
for flag in vx_6_symbol_type_enum:
    vx_6_sym_enum.add(vx_6_symbol_type_enum[flag], flag)

vx_5_symtbl_dt = StructureDataType("VX_5_SYMBOL_IN_TBL", 0x10)
vx_5_symtbl_dt.replaceAtOffset(0, unsigned_int_type, 4, "symHashNode", "")
vx_5_symtbl_dt.replaceAtOffset(4, char_ptr_type, 4, "symNamePtr", "")
vx_5_symtbl_dt.replaceAtOffset(8, void_ptr_type, 4, "symPrt", "")
vx_5_symtbl_dt.replaceAtOffset(0x0c, short_data_type, 4, "symGroup", "")
vx_5_symtbl_dt.replaceAtOffset(0x0e, vx_5_sym_enum, 1, "symType", "")
vx_5_symtbl_dt.replaceAtOffset(0x0f, byte_data_type, 1, "End", "")

vx_6_symtbl_dt = StructureDataType("VX_6_SYMBOL_IN_TBL", 0x14)
vx_6_symtbl_dt.replaceAtOffset(0, unsigned_int_type, 4, "symHashNode", "")
vx_6_symtbl_dt.replaceAtOffset(4, char_ptr_type, 4, "symNamePtr", "")
vx_6_symtbl_dt.replaceAtOffset(8, void_ptr_type, 4, "symPrt", "")
vx_6_symtbl_dt.replaceAtOffset(0x0c, unsigned_int_type, 4, "symRef", "moduleId of module, or predefined SYMREF")
vx_6_symtbl_dt.replaceAtOffset(0x10, short_data_type, 4, "symGroup", "")
vx_6_symtbl_dt.replaceAtOffset(0x12, vx_6_sym_enum, 1, "symType", "")
vx_6_symtbl_dt.replaceAtOffset(0x13, byte_data_type, 1, "End", "")

vx_5_sys_symtab = StructureDataType("VX_5_SYSTEM_SYMBOL_TABLE", 0x3C)
vx_5_sys_symtab.replaceAtOffset(0x00, void_ptr_type, 4, "objCore", "Pointer to object's class")
vx_5_sys_symtab.replaceAtOffset(0x04, void_ptr_type, 4, "nameHashId", "Pointer to HASH_TBL")
vx_5_sys_symtab.replaceAtOffset(0x08, char_data_type, 0x28, "symMutex", "symbol table mutual exclusion sem")
vx_5_sys_symtab.replaceAtOffset(0x30, void_ptr_type, 4, "symPartId", "memory partition id for symbols")
vx_5_sys_symtab.replaceAtOffset(0x34, unsigned_int_type, 4, "sameNameOk", "symbol table name clash policy")
vx_5_sys_symtab.replaceAtOffset(0x38, unsigned_int_type, 4, "PART_ID", "current number of symbols in table")


vx_5_hash_tbl = StructureDataType("VX_5_HASH_TABLE", 0x18)
vx_5_hash_tbl.replaceAtOffset(0x00, void_ptr_type, 4, "objCore", "Pointer to object's class")
vx_5_hash_tbl.replaceAtOffset(0x04, unsigned_int_type, 4, "elements", "Number of elements in table")
vx_5_hash_tbl.replaceAtOffset(0x08, void_ptr_type, 4, "keyCmpRtn", "Comparator function")
vx_5_hash_tbl.replaceAtOffset(0x0c, void_ptr_type, 4, "keyRtn", "Pointer to object's class")
vx_5_hash_tbl.replaceAtOffset(0x10, unsigned_int_type, 4, "keyArg", "Hash function argument")
vx_5_hash_tbl.replaceAtOffset(0x14, void_ptr_type, 4, "*pHashTbl", "Pointer to hash table array")

vx_5_sl_list = StructureDataType("VX_5_HASH_TABLE_LIST", 0x08)
vx_5_sl_list.replaceAtOffset(0x00, void_ptr_type, 4, "head", "header of list")
vx_5_sl_list.replaceAtOffset(0x04, void_ptr_type, 4, "tail", "tail of list")


def add_symbol(symbol_name, symbol_name_address, symbol_address, symbol_type):
    symbol_address = toAddr(symbol_address)
    symbol_name_string = symbol_name

    # Get symbol_name
    if symbol_name_address:
        symbol_name_address = toAddr(symbol_name_address)
        if getDataAt(symbol_name_address):
            print("removeDataAt: %s" % symbol_name_address)
            removeDataAt(symbol_name_address)

        try:
            symbol_name_string = createAsciiString(symbol_name_address).getValue()
            print("symbol_name_string: %s" % symbol_name_string)

        except CodeUnitInsertionException as err:
            print("Got CodeUnitInsertionException: {}".format(err))

        except:
            return

    if getInstructionAt(symbol_address):
        print("removeInstructionAt: %s" % symbol_address)
        removeInstructionAt(symbol_address)

    # Demangle symName
    try:
        # Demangle symName
        sym_demangled_name = None
        if can_demangle:
            try:
                sym_demangled = demangler.demangle(symbol_name_string, True)

                if not sym_demangled:
                    # some mangled function name didn't start with mangled prefix
                    sym_demangled = demangler.demangle(symbol_name_string, False)

                if not sym_demangled:
                    # Temp fix to handle _ prefix function name by remove _ prefix before demangle
                    sym_demangled = demangler.demangle(symbol_name_string[1:], False)

                if sym_demangled:
                    sym_demangled_name = sym_demangled.getSignature(False)

            except DemangledException as err:
                sym_demangled_name = None

            if sym_demangled_name:
                print("sym_demangled_name: %s" % sym_demangled_name)

        if symbol_name_string and (symbol_type in need_create_function):
            print("Start disassemble function %s at address %s" % (symbol_name_string, symbol_address.toString()))
            disassemble(symbol_address)
            # TODO: find out why createFunction didn't set the function name.
            function = createFunction(symbol_address, symbol_name_string)
            # use createLabel to rename function for now.
            createLabel(symbol_address, symbol_name_string, True)
            if function and sym_demangled_name:
                # Add demangled string to comment
                codeUnit = listing.getCodeUnitAt(symbol_address)
                codeUnit.setComment(codeUnit.PLATE_COMMENT, sym_demangled_name)
                # Rename function
                function_return, function_name, function_parameters = demangle_function(sym_demangled_name)
                print("Demangled function name is: %s" % function_name)
                print("Demangled function return is: %s" % function_return)
                print("Demangled function parameters is: %s" % function_parameters)
                function.setName(function_name, SourceType.USER_DEFINED)
                # Todo: Add parameters later
        else:
            createLabel(symbol_address, symbol_name_string, True)
            if sym_demangled_name:
                codeUnit = listing.getCodeUnitAt(symbol_address)
                codeUnit.setComment(codeUnit.PLATE_COMMENT, sym_demangled_name)

    except Exception as err:
        print("Create function Failed: %s" % err)

    except:
        print("Create function Failed: Java error")


def fix_symbol_table_structs(symbol_table_start, symbol_table_end, vx_version):
    symbol_interval = 16
    dt = vx_5_symtbl_dt
    if vx_version == 6:
        symbol_interval = 20
        dt = vx_6_symtbl_dt

    # Create symbol table structs
    symbol_table_start_addr = toAddr(symbol_table_start)
    symbol_table_end_addr = toAddr(symbol_table_end)

    ea = symbol_table_start_addr
    sym_length = (symbol_table_end - symbol_table_start) // symbol_interval
    createLabel(symbol_table_start_addr, "vxSymTbl", True)
    clearListing(symbol_table_start_addr, symbol_table_end_addr)
    vx_symbol_array_data_type = ArrayDataType(dt, sym_length, dt.getLength())
    createData(symbol_table_start_addr, vx_symbol_array_data_type)


def is_vx_symbol_file(file_data, is_big_endian=True):
    # Check key function names
    for key_function in function_name_key_words:
        if key_function not in file_data:
            print("key function not found")
            return False

    if is_big_endian:
        return struct.unpack('>I', file_data[:4])[0] == len(file_data)

    else:
        return struct.unpack('<I', file_data[:4])[0] == len(file_data)