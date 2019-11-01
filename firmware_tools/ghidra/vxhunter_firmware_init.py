# coding=utf-8
from vxhunter_core import *
from ghidra.util.task import TaskMonitor
from ghidra.program.model.symbol.SourceType import USER_DEFINED
from ghidra.program.model.util import CodeUnitInsertionException
from ghidra.app.util.demangler import DemangledException
from ghidra.app.util.demangler.gnu import GnuDemangler
from ghidra.program.model.listing.CodeUnit import PLATE_COMMENT
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

# Init VxWorks symbol table structs
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



try:
    vx_version = askChoice("Choice", "Please choose VxWorks main Version ", ["5.x", "6.x"], "5.x")
    if vx_version == u"5.x":
        vx_version = 5

    elif vx_version == u"6.x":
        vx_version = 6

    if vx_version:
        firmware_path = currentProgram.domainFile.getMetadata()['Executable Location']
        firmware = open(firmware_path, 'rb').read()
        target = VxTarget(firmware=firmware, vx_version=vx_version)
        # target.logger.setLevel(logging.DEBUG)
        target.quick_test()
        if target.load_address is None:
            target.find_loading_address()
        demangler = GnuDemangler()
        listing = currentProgram.getListing()
        can_demangle = demangler.canDemangle(currentProgram)
        if target.load_address:
            ghidra_sym_tbl = currentProgram.getSymbolTable()
            load_address = target.load_address
            target.logger.info("load_address:%s" % hex(load_address))

            # Rebase_image
            target_block = currentProgram.memory.blocks[0]
            print("target_block: %s" % target_block)
            address = toAddr(load_address)
            print("address: %s" % address)
            currentProgram.memory.moveBlock(target_block, address, TaskMonitor.DUMMY)

            # Create symbol table structs
            symbol_table_start = toAddr(target.symbol_table_start + target.load_address)
            symbol_table_end = toAddr(target.symbol_table_end + target.load_address)
            symbol_interval = 16
            dt = vx_5_symtbl_dt
            if vx_version == 6:
                symbol_interval = 20
                dt = vx_6_symtbl_dt
            ea = symbol_table_start
            sym_length = (target.symbol_table_end - target.symbol_table_start) // symbol_interval
            createLabel(symbol_table_start, "vxSymTbl", True)
            clearListing(symbol_table_start, symbol_table_end)
            vx_symbol_array_data_type = ArrayDataType(dt, sym_length, dt.getLength())
            createData(symbol_table_start, vx_symbol_array_data_type)

            # Rename functions
            while ea < symbol_table_end:
                symbol_name_string = None
                offset = 4
                symbol_flag = getInt(ea.add(symbol_interval - 4))
                symbol_name_address = toAddr(getInt(ea.add(offset)))
                symbol_dest_address = toAddr(getInt(ea.add(offset + 4)))
                print("symbol_address: %s" % ea)
                print("symbol_flag: %s" % symbol_flag)
                print("symbol_name_address: %s" % symbol_name_address)
                print("symbol_dest_address: %s" % symbol_dest_address)
                if not symbol_dest_address:
                    ea = ea.add(symbol_interval)
                    continue

                # Get symbol_name
                if getDataAt(symbol_name_address):
                    print("removeDataAt: %s" % symbol_name_address)
                    removeDataAt(symbol_name_address)
                if getInstructionAt(symbol_dest_address):
                    print("removeInstructionAt: %s" % symbol_dest_address)
                    removeInstructionAt(symbol_dest_address)

                try:
                    symbol_name_string = createAsciiString(symbol_name_address).getValue()
                    print("symbol_name_string: %s" % symbol_name_string)
                except CodeUnitInsertionException as err:
                    # Todo: Need find a way to get subString
                    print("Got CodeUnitInsertionException: {}".format(err))
                    ea = ea.add(symbol_interval)
                    continue

                except:
                    ea = ea.add(symbol_interval)
                    continue

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

                    if symbol_name_string and (symbol_flag in need_create_function):
                        print("Start disassemble function %s at address %s" % (symbol_name_string,
                                                                               symbol_dest_address.toString()))
                        disassemble(symbol_dest_address)
                        # TODO: find out why createFunction didn't set the function name.
                        function = createFunction(symbol_dest_address, symbol_name_string)
                        # use createLabel to rename function for now.
                        createLabel(symbol_dest_address, symbol_name_string, True)
                        if function and sym_demangled_name:
                            # Add demangled string to comment
                            codeUnit = listing.getCodeUnitAt(symbol_dest_address)
                            codeUnit.setComment(codeUnit.PLATE_COMMENT, sym_demangled_name)
                            # Rename function
                            function_return, function_name, function_parameters = demangle_function(sym_demangled_name)
                            print("Demangled function name is: %s" % function_name)
                            print("Demangled function return is: %s" % function_return)
                            print("Demangled function parameters is: %s" % function_parameters)
                            function.setName(function_name, USER_DEFINED)
                            # Todo: Add parameters later
                    else:
                        createLabel(symbol_dest_address, symbol_name_string, True)
                        if sym_demangled_name:
                            codeUnit = listing.getCodeUnitAt(symbol_dest_address)
                            codeUnit.setComment(codeUnit.PLATE_COMMENT, sym_demangled_name)

                except Exception as err:
                    print("Create function Failed: %s" % err)

                except:
                    print("Create function Failed: Java error")

                print("keep going!")
                ea = ea.add(symbol_interval)

        else:
            popup("Can't find symbols in binary")

except Exception as err:
    print(err)
