# coding=utf-8
from ghidra.app.util.demangler import DemangledException
from ghidra.app.util.demangler.gnu import GnuDemangler
from ghidra.program.model.mem import Memory
from ghidra.util.task import TaskMonitor
import struct
import logging
import time


# The Python module that Ghidra directly launches is always called __main__.  If we import
# everything from that module, this module will behave as if Ghidra directly launched it.
from __main__ import *


debug = False
process_is_64bit = False

# Init Default Logger
logger = logging.getLogger('Default_logger')
logger.setLevel(logging.INFO)
console_handler = logging.StreamHandler()
console_format = logging.Formatter('[%(levelname)-8s][%(module)s.%(funcName)s] %(message)s')
console_handler.setFormatter(console_format)
logger.addHandler(console_handler)

if debug:
    logger.setLevel(logging.DEBUG)

endian = currentProgram.domainFile.getMetadata()[u'Endian']
if endian == u'Big':
    is_big_endian = True
else:
    is_big_endian = False


process_type = currentProgram.domainFile.getMetadata()[u'Processor']
if process_type.endswith(u'64'):
    process_is_64bit = True


demangler = GnuDemangler()
listing = currentProgram.getListing()
can_demangle = demangler.canDemangle(currentProgram)


def is_address_in_current_program(address):
    for block in currentProgram.memory.blocks:
        if block.getStart().offset <= address.offset <= block.getEnd().offset:
            return True
    return False


def get_signed_value(input_data):
    pack_format = ""
    if is_big_endian:
        pack_format += ">"
    else:
        pack_format += "<"

    if process_is_64bit:
        pack_format += "L"
    else:
        pack_format += "I"

    logger.debug("type(input_data): {}".format(type(input_data)))
    data = struct.pack(pack_format.upper(), input_data)
    signed_data = struct.unpack(pack_format.lower(), data)[0]

    return signed_data


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


def create_uninitialized_block(block_name, start_address, length, overlay=False):
    # createUninitializedBlock

    try:
        memory = currentProgram.memory
        memory.createUninitializedBlock(block_name, start_address, length, overlay)
        return True

    except:
        return False


def create_initialized_block(block_name, start_address, length, fill=0x00, monitor=TaskMonitor.DUMMY, overlay=False):
    # createUninitializedBlock

    try:
        memory = currentProgram.memory
        memory.createInitializedBlock(block_name, start_address, length, fill, monitor, overlay)
        return True

    except:
        return False
