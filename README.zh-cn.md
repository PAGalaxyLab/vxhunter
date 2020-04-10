# VxHunter
一个用于VxWorks嵌入式设备分析的工具集。

*说明文档的其他语言: [English](README.md), [简体中文](README.zh-cn.md)*


## Firmware Analyze Tool
固件分析工具是基于python编写的VxWorks分析工具，主要的用途是分析固件的加载地址，从识别出的符号表中修复函数名及符号信息等。

支持的逆向工具:
* IDA Pro 7.x
* Ghidra 9.x
* Radare2

测试过的固件:
* Schneider 140NOE77101 - Ethernet network TCP/IP module
* Siemens SCALANCE-X208/SCALANCE-X216/SCALANCE-X308 - Siemens SCALANCE X Switch
* Hirschmann PowerMICE - Industrial ETHERNET Switch


### IDA Demo
![](docs/images/VxHunter_IDA_480.gif)


### Ghidra Demo
[如何在Ghidra中使用VxHunter](docs/How_to_use_vxhunter_firmware_tools_in_ghidra.zh-cn.md)


#### vxhunter_firmware_init.py
![](docs/images/VxHunter_ghidra_firmware_init_720.gif)


#### vxhunter_analysis.py
在执行了`vxhunter_firmware_init.py`后，我们可以使用`vxhunter_analysis.py`脚本对VxWorks固件进行进一步的分析。
这个脚本会分析硬编码的账号，已编译的VxWorks服务以及一些其他的信息。
![](docs/images/VxHunter_ghidra_analysis_720.gif)


### Radare2 Demo

[如何在Radare2中使用VxHunter](docs/How_to_use_vxhunter_firmware_tools_in_radare2.zh-cn.md)

![](docs/images/VxHunter_Radare2_720.gif)
 
## VxSerial Debugger - Beta
串口调试工具是基于VxWorks命令行及python编写的一个VxWorks调试工具，通常我们能够在VxWorks设备的串口获取到交互式命令行。

串口调试工具使用VxWorks交互式命令行中的内存读/写指令来将调试shellcode注入到目标系统中，这个调试shellcode将由keystone-engine来动态生成。

串口调试工具的原理和inline hook比较像，如果目标设备命中了断点，它将会跳转执行调试shellcode并且等待其他调试命令的执行。

串口调试工具所支持的功能:
* 内存读/写。
* 条件断点, 基于Python的callback函数，该函数返回True则断下，返回False时程序会继续执行。
* 查看Task状态。(栈, 寄存器).
* VxWorks数据结构查看(netpool, clBlk, 等).


### Example
这个示例脚本是在TP-Link TL-WR886N-V7，固件版本V1.1.0的设备上调试CVE-2018-19528漏洞的例子。


[串口调试示例脚本](serial_debugger_example.py)

示例视频

[![示例视频](https://img.youtube.com/vi/ulO8MsoDLLk/0.jpg)](https://www.youtube.com/watch?v=ulO8MsoDLLk)


## TODO
### Firmware Analyze Tool
* ~~支持对VxWorks内存dump文件分析~~
* 支持分析VxWorks内存dump文件中动态加载的符号
* 支持分析symFindByName符号查询函数的引用来补全函数引用。
