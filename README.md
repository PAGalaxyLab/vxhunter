# VxHunter 
A ToolSet for VxWorks Based Embedded Device Analyses.


## Firmware Analyze Tool
The firmware analyze tool is plugins written in Python, mainly used for analyze firmware loading address, fix function name with symbol table and etc.

supported reverse tool: 
* IDA Pro 7.x
* ghidra 9.0.1

Firmware analyze tool is tested with follow devices firmware:
* Schneider 140NOE77101 - Ethernet network TCP/IP module
* Siemens SCALANCE-X208/SCALANCE-X216/SCALANCE-X308 - Siemens SCALANCE X Switch
* Hirschmann PowerMICE - Industrial ETHERNET Switch


## VxSerial Debugger - will opensource soon
The serial debugger tool is written in Python and based on VxWorks command line, usually we can get that command line from VxWorks device using serial port. 

The serial debugger tool using memory read/write command to inject debugger shellcode into targat system, the shellcode is dynamic generation by keystone-engine. 

It's similar to inline hook, if target hit the breakpoint, it will jump to debugger shellcode and waiting for other debug command. 

The serial debugger tool support functions:
* Memory read/write function.
* Conditional breakpoint, Python based conditional function, return True to break, False to keep running.
* Task status viewer(stacks, register).
* VxWorks struct viewer(netpool, clBlk, etc).