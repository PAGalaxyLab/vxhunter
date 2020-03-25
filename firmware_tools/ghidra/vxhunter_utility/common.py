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
def get_logger(name="Default_logger"):
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    console_handler = logging.StreamHandler()
    console_format = logging.Formatter('[%(levelname)-8s][%(module)s.%(funcName)s] %(message)s')
    console_handler.setFormatter(console_format)
    logger.addHandler(console_handler)
    return logger


logger = get_logger()


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


class Timer(object):
    def __init__(self):
        self.start_time = None

    def reset(self):
        self.start_time = time.time()

    def start_timer(self):
        if self.start_time:
            return False
        else:
            self.start_time = time.time()
            return self.start_time

    def get_timer(self):
        if self.start_time:
            return time.time() - self.start_time
        return False


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
