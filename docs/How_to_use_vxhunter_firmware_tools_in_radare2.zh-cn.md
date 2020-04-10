# 如何在Radare2中使用VxHunter

VxHunter radare2脚本能自动分析VxWorks镜像的加载地址及符号信息。


## 步骤一: 在radare2中打开VxWorks镜像
示例固件 [下载地址](https://github.com/dark-lbp/vxhunter/tree/master/example_firmware), 在这里我们使用固件是[image_vx5_ppc_big_endian.bin](https://github.com/dark-lbp/vxhunter/blob/master/example_firmware/image_vx5_ppc_big_endian.bin).

在radare2使用正确的处理器类型来加载VxWorks镜像。

```
r2 -a ppc -b 32 image_vx5_ppc_big_endian.bin
```

## 步骤二: 使用R2pipe运行VxHunter r2 python脚本

目前已经编写了python2及python3两个版本的脚本。

```
# for python2
#!pipe python2 ./vxhunter_r2_py2.py

# for python3
#!pipe python3 ./vxhunter_r2_py3.py
```

VxHunter r2能够利用关键字自动识别VxWorks版本号。如果VxHunter无法识别VxWorks版本，就需要用户在r2中输入对应版本。

```
[0x00000000]> #!pipe python3 ./vxhunter_r2_py3.py # for python2
Running with python version: 3.7.4 (default, Sep  7 2019, 18:27:02)
[Clang 10.0.1 (clang-1001.0.46.4)]
Auto detected VxWorks version: None
Please input the VxWorks main version type 'c' to exit
Available (5/6/c): 5
vx_version:5
```

你也可以将VxWorks版本作为第一个脚本参数来传参:

```
[[0x00000000]> #!pipe python3 ./vxhunter_r2_py3.py 5
Running with python version: 3.7.4 (default, Sep  7 2019, 18:27:02)
[Clang 10.0.1 (clang-1001.0.46.4)]
vx_version:5
firmware_path: /path/image_vx5_ppc_big_endian.bin
[INFO    ][vxhunter_r2_py3.find_symbol_table] symbol table start offset: 0x301e60
[INFO    ][vxhunter_r2_py3.find_symbol_table] symbol table end offset: 0x3293b0
```

VxHunter会分析VxWorks镜像的加载地址及符号，如果分析成功你会受到如下所示的输出。

```
###### Start analyze firmware ######

[INFO    ][vxhunter_r2_py3.quick_test] load address is not:0x80002000
[INFO    ][vxhunter_r2_py3._check_load_address] load address is :0x10000
Found VxWorks image load address: 0x00010000
Found VxWorks symbol table from 0x00301E60 to 0x003293B0

###### Rebase current firmware ######

All core files, io, anal and flags info purged.
Rebase with r2 command: o /Users/zhuwz/temp/VxHunter_r2/image_vx5_ppc_big_endian.bin 0x10000 r-x

###### Start analyzing functions######

symbol_table_start_address: 0x00311E60
symbol_table_end_address: 0x003393B0
af: Cannot find function at 0x0002986c
af: Cannot find function at 0x0002983c
af: Cannot find function at 0x002275b0
... 


###### Finish here is the flags ######
    0 . classes
 9086 . functions
    0 . relocs
    0 . sections
    0 . segments
 2155 * symbols
```

## 步骤三: Have Fun

至此就可以自由的对这个VxWorks固件进行分析了。

### 查找函数
```
[0x00000000]> f functions
[0x00000000]> f |grep usrI
0x0002b8e4 180 usrIpLibInit
0x0002cd94 88 usrInit
0x0002d1d8 80 usrIosCoreInit
0x0002d228 100 usrIosExtraInit
```

### 查看函数
![](images/VxHunter_Rarare2_view_functions.png)
