# coding=utf-8
import logging
import struct
from ghidra.util.task import TaskMonitor
from ghidra.program.model.symbol.SourceType import USER_DEFINED


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


def get_string(offset):
    string = ""
    while True:
        if string_table[offset] != '\x00':
            string += string_table[offset]
            offset += 1
        else:
            break
    return string


def load_symbols(file_data, is_big_endian=True):
    symbol_list = []
    if is_big_endian:
        unpack_format = '>I'
    else:
        unpack_format = '<I'

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
    print("3")
    # load symbols
    for symbol_data in symbol_list:
        flag, symbol_name, symbol_address = symbol_data
        symbol_address = toAddr(symbol_address)
        if flag == 0x54:
            print("Start fix Function %s at 0x%s" % (symbol_name, symbol_address))
            if getInstructionAt(symbol_address):
                print("removeInstructionAt: %s" % symbol_address)
                removeInstructionAt(symbol_address)
            try:
                disassemble(symbol_address)
                createFunction(symbol_address, symbol_name)
                if getFunctionAt(symbol_address):
                    getFunctionAt(symbol_address).setName(symbol_name, USER_DEFINED)

            except Exception as err:
                pass


try:
    symbol_file = askFile("Open symbol file", "")
    symbol_file_data = file(symbol_file.absolutePath).read()
    if is_vx_symbol_file(symbol_file_data):
        load_symbols(symbol_file_data)

except Exception as err:
    print(err)
