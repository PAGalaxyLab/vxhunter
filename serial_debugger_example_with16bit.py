# !/usr/bin/env python2
# coding=utf-8
from serial_debuger.vx5_mips_debugger import *
from serial_debuger.serialtube import serialtube
import logging
import socket
import time


def wait_move_on(print_string):
    print(print_string)
    move_on = False
    while move_on is False:
        ans = raw_input("Y/y to move on,\n:")
        if ans.upper() == "Y":
            move_on = True
    return

serial_port = "/dev/ttyUSB2"
debugger = Vx5MipsDebugger(endian=2,cache_update_address=0x800C9B51 #flag 1 is for 16bit
,process_type='MIPSLE')
debugger.serial = serialtube(port=serial_port,baudrate=57600)
#debugger.logger.setLevel(logging.DEBUG)
debugger.init_debugger(0x8014BA00)

#flag 1 for 16bit
debugger.add_break_point(0x800F77F0,1)

task = debugger.wait_break()
wait_move_on('success break!')

print("Resume task")
debugger.task_resume(task)

