# coding=utf-8
import logging
import struct
from ghidra.util.task import TaskMonitor
from ghidra.program.model.symbol.SourceType import USER_DEFINED
from ghidra.app.util.demangler import DemangledException
from ghidra.app.util.demangler.gnu import GnuDemangler
from ghidra.program.model.listing.CodeUnit import PLATE_COMMENT


function_name_key_words = ['bzero', 'usrInit', 'bfill']


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


def demangle_function(demangle_string):
    function_return = None
    function_parameters = None
    function_name_end = len(demangle_string)

    # get parameters
    index = len(demangle_string) - 1
    if demangle_string[-1] == ')':
        # have parameters
        parentheses_count = 0
        while index >= 0:
            if demangle_string[index] == ')':
                parentheses_count += 1

            elif demangle_string[index] == '(':
                parentheses_count -= 1

            index -= 1

            if parentheses_count == 0:
                break

        function_parameters = demangle_string[index + 2:-1]
        function_name_end = index

    # get function name
    while index >= 0:
        if demangle_string[index] == ' ':
            break
        else:
            index -= 1
    function_name_start = index
    function_name = demangle_string[function_name_start + 1:function_name_end + 1]

    # get function return
    function_return = demangle_string[:function_name_start]
    return function_return, function_name, function_parameters


def load_symbols(file_data, is_big_endian=True):
    symbol_list = []
    if is_big_endian:
        unpack_format = '>I'
    else:
        unpack_format = '<I'

    # Init demangler
    demangler = GnuDemangler()
    can_demangle = demangler.canDemangle(currentProgram)
    symbol_count = struct.unpack(unpack_format, file_data[4:8])[0]
    print("symbol_count: %s" % symbol_count)
    symbol_offset = 8
    string_table_offset = 8 + 8 * symbol_count
    print("string_table_offset: %s" % string_table_offset)
    # get symbols
    for i in range(symbol_count):
        offset = i * 8
        symbol_data = file_data[symbol_offset + offset:symbol_offset + offset + 8]
        flag = ord(symbol_data[0])
        string_offset = struct.unpack(unpack_format, '\x00' + symbol_data[1:4])[0]
        string_offset += string_table_offset
        print("string_offset: %s" % string_offset)
        symbol_name = ""
        while True:
            if file_data[string_offset] != '\x00':
                symbol_name += file_data[string_offset]
                string_offset += 1

            else:
                break
        print("symbol_name: %s" % symbol_name)
        symbol_address = struct.unpack(unpack_format, symbol_data[-4:])[0]
        symbol_list.append([flag, symbol_name, symbol_address])
        # Find TP-Link device loading address with symbols
        if "wrs_kernel_text_start" in symbol_name:
            load_address = symbol_address
            target_block = currentProgram.memory.blocks[0]
            print("target_block: %s" % target_block)
            address = toAddr(load_address)
            print("address: %s" % address)
            currentProgram.memory.moveBlock(target_block, address, TaskMonitor.DUMMY)

    # load symbols
    for symbol_data in symbol_list:
        flag, symbol_name, symbol_address = symbol_data
        symbol_address = toAddr(symbol_address)
        # Demangle symbol_name
        sym_demangled_name = None
        if can_demangle:
            try:
                sym_demangled = demangler.demangle(symbol_name, True)

                if not sym_demangled:
                    # some mangled function name didn't start with mangled prefix
                    sym_demangled = demangler.demangle(symbol_name, False)

                if sym_demangled:
                    sym_demangled_name = sym_demangled.getSignature(False)

            except DemangledException:
                sym_demangled_name = None

            if sym_demangled_name:
                print("sym_demangled_name: %s" % sym_demangled_name)

        if flag == 0x54:
            print("Start fix Function %s at 0x%s" % (symbol_name, symbol_address))
            if getInstructionAt(symbol_address):
                print("removeInstructionAt: %s" % symbol_address)
                removeInstructionAt(symbol_address)
            try:
                disassemble(symbol_address)
                function = createFunction(symbol_address, symbol_name)
                if function and sym_demangled_name:
                    # Add demangled string to comment
                    codeUnit = listing.getCodeUnitAt(symbol_address)
                    codeUnit.setComment(codeUnit.PLATE_COMMENT, sym_demangled_name)
                    # Rename function
                    function_return, function_name, function_parameters = demangle_function(sym_demangled_name)
                    print("Demangled function name is: %s" % function_name)
                    print("Demangled function return is: %s" % function_return)
                    print("Demangled function parameters is: %s" % function_parameters)
                    function.setName(function_name, USER_DEFINED)

                if getFunctionAt(symbol_address):
                    getFunctionAt(symbol_address).setName(symbol_name, USER_DEFINED)

            except Exception as err:

                print("Create function Failed: %s" % err)

        else:
            try:
                print("Start add label %s at address: %s" % (symbol_name, symbol_address))
                createLabel(symbol_address, symbol_name, True)

            except:
                print("Can't add label")

try:
    symbol_file = askFile("Open symbol file", "")
    symbol_file_data = file(symbol_file.absolutePath).read()
    if is_vx_symbol_file(symbol_file_data):
        load_symbols(symbol_file_data)

except Exception as err:
    print(err)
