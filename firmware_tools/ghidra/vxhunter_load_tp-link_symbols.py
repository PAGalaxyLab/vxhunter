# coding=utf-8
import logging
import struct
from vxhunter_utility.symbol import *
from ghidra.util.task import TaskMonitor


def load_symbols(file_data, is_big_endian=True):
    symbol_list = []
    if is_big_endian:
        unpack_format = '>I'
    else:
        unpack_format = '<I'

    # Init demangler
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
        symbol_flag, symbol_name, symbol_address = symbol_data
        # TODO: Need Map symbol_flag correct, currently just map 0x54 to 0x05.
        if symbol_flag == 0x54:
            symbol_flag = 0x05
        # Flag is different
        add_symbol(symbol_name, None, symbol_address, symbol_flag)


try:
    symbol_file = askFile("Open symbol file", "")
    symbol_file_data = file(symbol_file.absolutePath).read()
    if is_vx_symbol_file(symbol_file_data):
        load_symbols(symbol_file_data)

except Exception as err:
    print(err)
