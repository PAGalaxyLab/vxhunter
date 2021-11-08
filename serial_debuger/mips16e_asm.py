#coding:utf8
import os
import binascii

def ASM16(code,endian = 1):
   template = '''
.section .shellcode,"awx"
.global _start
.global __start
_start:
__start:
.set mips2
.set noreorder
%s
   ''' % code
   f = open('1.binary.s','wb')
   f.write(template)
   f.close()
   e = '-EL' if endian == 2 else '-EB'
   os.system("mips-linux-gnu-as %s -mips16 -o 1.binary.tmp 1.binary.s" % e)
   os.system('rm 1.binary.s')
   os.system('mips-linux-gnu-objcopy -j .shellcode -Obinary 1.binary.tmp')
   f = open('1.binary.tmp','rb')
   content = f.read()
   f.close()
   os.system('rm 1.binary.tmp')
   return content
