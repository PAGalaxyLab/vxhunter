# coding=utf-8
import logging
import os
import time
import struct
import curses.ascii
import idc
import idaapi
from idc import GetOpType, GetOpnd, ItemEnd

default_check_count = 100

known_address = [0x80002000, 0x10000, 0x1000, 0xf2003fe4, 0x100000, 0x107fe0]

symbol_format_sign_5 = [
    '\x00\x00\x05\x00',
    '\x00\x00\x07\x00',
    '\x00\x00\x09\x00',
    '\x00\x00\x11\x00'
]

symbol_format_sign_6 = [
    '\x00\x00\x00\x00\x00\x00\x03\x00',  # Unknown Type (Might not function name)
    '\x00\x00\x00\x00\x00\x00\x05\x00',
    '\x00\x00\x00\x00\x00\x00\x07\x00',
    '\x00\x00\x00\x00\x00\x00\x09\x00',
    '\x00\x00\x00\x00\x00\x00\x11\x00'
]


class VxTarget(object):
    def __init__(self, firmware, vx_version=5, endian=None, logger=None):
        '''
        :param firmware: data of firmware
        :param vx_version: 5 = VxWorks 5.x; 6= VxWorks 6.x
        :param endian: 1 = big endian; 2 = little endian
        :param logger: logger for the target (default: None)
        '''
        self._endian = endian
        self._vx_version = vx_version
        self.symbol_table_start = None
        self.symbol_table_end = None
        self._string_table = []
        self._symbol_table = []
        self.load_address = None
        self._firmware = firmware
        self._has_symbol = None
        if self._vx_version == 5:
            self._symbol_interval = 16
        elif self._vx_version == 6:
            self._symbol_interval = 20
        if logger is None:
            self.logger = logging.getLogger('target')
            self.logger.setLevel(logging.INFO)
            consolehandler = logging.StreamHandler()
            console_format = logging.Formatter('[%(levelname)-8s][%(module)s.%(funcName)s] %(message)s')
            consolehandler.setFormatter(console_format)
            self.logger.addHandler(consolehandler)
        else:
            self.logger = logger

    def prepare(self):
        self.find_symbol_table()
        self.get_symbol_table()

    def _check_vxworks_endian(self):
        data1 = self._firmware[self.symbol_table_start + 4:self.symbol_table_start + 4 + self._symbol_interval]
        data2 = self._firmware[self.symbol_table_start + 4 + self._symbol_interval:self.symbol_table_start +
                                                                                   4 + self._symbol_interval * 2]
        if data1[0:2] == data2[0:2]:
            self._endian = 1
        elif data1[2:4] == data2[2:4]:
            self._endian = 2
        else:
            self._endian = 2

    def _check_symbol_format(self, offset):
        data = self._firmware[offset:offset + self._symbol_interval * 10]
        is_big_edian = True
        is_little_edian = True
        if self._vx_version == 5:
            self.logger.debug("Check VxWorks 5 symbol format")
            for i in range(10):
                data1 = data[i * self._symbol_interval:(i + 1) * self._symbol_interval]
                sign_match = False
                # format simple check
                if data1[:4] != '\x00\x00\x00\x00':
                    return False
                if data1[4:8] == '\x00\x00\x00\x00':
                    return False
                if data1[8:12] == '\x00\x00\x00\x00':
                    return False
                # check sign
                for sign in symbol_format_sign_5:
                    if data1[-4:] == sign:
                        sign_match = True
                        break
                if sign_match is False:
                    self.logger.debug("Didn't match any sign")
                    return False

            # check is big endian
            for i in range(9):
                data1 = data[4 + i * self._symbol_interval:6 + i * self._symbol_interval]
                data2 = data[4 + (i + 1) * self._symbol_interval:6 + (i + 1) * self._symbol_interval]
                if data1 != data2:
                    self.logger.debug("is not big endian")
                    is_big_edian = False
                    break

            # check is little endian
            for i in range(9):
                data1 = data[6 + i * self._symbol_interval:8 + i * self._symbol_interval]
                data2 = data[6 + (i + 1) * self._symbol_interval:8 + (i + 1) * self._symbol_interval]
                if data1 != data2:
                    self.logger.debug("is not little endian")
                    is_little_edian = False
                    break

            return is_big_edian ^ is_little_edian

        elif self._vx_version == 6:
            self.logger.debug("Check VxWorks 6 symbol format")
            # TODO: Need fix VxWorks version 6.x
            for i in range(10):
                # format simple check
                data1 = data[i * self._symbol_interval:(i + 1) * self._symbol_interval]
                if data1[:4] != '\x00\x00\x00\x00':
                    return False
                if data1[4:8] == '\x00\x00\x00\x00':
                    return False
                if data1[8:12] == '\x00\x00\x00\x00':
                    return False
                # TODO: Need handle this problem
                # if symbol_format sign is '\x00\x00\x00\x00\x00\x00\x03\x00' sometime data1[8:12] will be '\x00\x00\x00\x00'
                # if data1[8:12] == '\x00\x00\x00\x00':
                #     return False

                # check sign
                # print(data1[-8:])
                if data1[-8:] not in symbol_format_sign_6:
                    return False
            return True

    def _check_symbol_format_simple(self, offset):
        if self._vx_version == 5:
            data1 = self._firmware[offset:offset + self._symbol_interval]
            if data1[:4] != '\x00\x00\x00\x00':
                return False
            if data1[4:8] == '\x00\x00\x00\x00':
                return False
            if data1[8:12] == '\x00\x00\x00\x00':
                return False
            for sign in symbol_format_sign_5:
                if data1[-4:] == sign:
                    return True
            return False
        elif self._vx_version == 6:
            data1 = self._firmware[offset:offset + self._symbol_interval]
            if data1[:4] != '\x00\x00\x00\x00':
                return False
            if data1[4:8] == '\x00\x00\x00\x00':
                return False
            # TODO: Need handle this problem
            # if symbol_format sign is '\x00\x00\x00\x00\x00\x00\x03\x00' sometime data1[8:12] will be '\x00\x00\x00\x00'
            # if data1[8:12] == '\x00\x00\x00\x00':
            #     return False
            if data1[-8:] in symbol_format_sign_6:
                return True
            return False

    def find_symbol_table(self):
        '''
        :return:
        '''
        for offset in range(len(self._firmware)):
            if self.symbol_table_start is None:
                if self._check_symbol_format(offset):
                    self.logger.info("symbol table start offset: %s" % (hex(offset)))
                    self.symbol_table_start = offset
                    self._has_symbol = True
                    break
            else:
                break

        if self.symbol_table_start:
            for i in range(self.symbol_table_start, len(self._firmware), self._symbol_interval):
                if self._check_symbol_format_simple(i):
                    self.symbol_table_end = i + self._symbol_interval
                else:
                    self.logger.info("symbol table end offset: %s" % hex(self.symbol_table_end))
                    break
        else:
            self.logger.error("didn't find symbol table in this image")
            self._has_symbol = False

    def get_symbol_table(self):
        if self.symbol_table_start and self.symbol_table_end:
            self._check_vxworks_endian()

        for i in range(self.symbol_table_start, self.symbol_table_end, self._symbol_interval):
            str_addr = self._firmware[i + 4:i + 8]
            func_addr = self._firmware[i + 8:i + 12]
            if self._endian == 1:
                unpack_format = '>I'
            elif self._endian == 2:
                unpack_format = 'I'
            string_addr = struct.unpack(unpack_format, str_addr)[0]
            function_addr = struct.unpack(unpack_format, func_addr)[0]
            self._symbol_table.append({
                'string_addr': str(hex(string_addr)),
                'length': None,
                'function_addr': str(hex(function_addr)),
                'offset': str(hex(i))
            })
        self._symbol_table = sorted(self._symbol_table, key=lambda x: x['string_addr'])
        for i in range(len(self._symbol_table) - 1):
            self._symbol_table[i]['length'] = int(self._symbol_table[
                                                      i + 1]['string_addr'], 16) - int(
                self._symbol_table[i]['string_addr'], 16)

    def _check_func_name(self, string):
        bad_str = ['\\', '%', '+', ',', '&', '/']
        # function name length should less than 255 byte
        if len(string) > 255:
            return False
        for data in bad_str:
            if data in string:
                return False
        for c in string:
            if curses.ascii.isprint(c) is False:
                return False
        return True

    def _get_string_data(self, offset):
        while offset < len(self._firmware):
            if self._firmware[offset].encode('hex') != '00':
                start_address = offset
                end_address = offset
                while offset <= len(self._firmware):
                    offset += 1
                    if self._firmware[offset].encode('hex') == '00':
                        end_address = offset
                        break
                data = self._firmware[start_address:end_address]
                return data, start_address, end_address
            else:
                offset += 1
        return None, None, None

    def find_string_table(self, offset):
        # TODO: 需要在符号表中String可能不连续的问题
        temp_str_tab_data = []
        if len(self._symbol_table) > default_check_count:
            count = default_check_count
        else:
            count = len(self._symbol_table)

        while offset < len(self._firmware):
            # find first printable char
            if curses.ascii.isprint(self._firmware[offset]) is True:
                # get string from offset
                string, start_address, end_address = self._get_string_data(offset)
                # check string is function name
                if self._check_func_name(string) is False:
                    if len(temp_str_tab_data) < count:
                        temp_str_tab_data = []
                        offset = end_address
                        continue
                    else:
                        start_offset = temp_str_tab_data[0][1]
                        end_offset = temp_str_tab_data[-1][2]
                        self.logger.info("found a string tab at: %s to %s" % (hex(start_offset), hex(end_offset)))
                        return start_offset, end_offset
                else:
                    temp_str_tab_data.append((string, start_address, end_address))

                # get next string from offset
                next_string, next_start_address, next_end_address = self._get_string_data(end_address)
                if next_start_address:
                    # strings interval should between 4
                    if 4 < (next_start_address - end_address):
                        offset = next_end_address
                        if len(temp_str_tab_data) < count:
                            temp_str_tab_data = []
                            continue
                        else:
                            start_offset = temp_str_tab_data[0][1]
                            end_offset = temp_str_tab_data[-1][2]
                            self.logger.info("found end %s to %s" % (hex(start_address), hex(end_address)))
                            self.logger.info("found a string tab at: %s to %s" % (hex(start_offset), hex(end_offset)))
                            return start_offset, end_offset
                    else:
                        offset = end_address
            else:
                offset += 1
        self.logger.error("can't find any string table this time")
        return None, None

    def get_string_table(self, str_start_address, str_end_address):
        self._string_table = []
        offset = str_start_address
        address = offset
        str_tab_data = []
        while offset <= str_end_address:
            if self._firmware[offset].encode('hex') == '00':
                while offset <= str_end_address:
                    offset += 1
                    if self._firmware[offset].encode('hex') != '00':
                        next_address = offset
                        string = self._firmware[address:next_address]
                        length = next_address - address
                        str_tab_data.append({
                            'address': str(hex(address)),
                            'string': string,
                            'length': length
                        })
                        offset = next_address
                        address = next_address
                        break
            else:
                offset += 1
        self._string_table = str_tab_data

    def _check_fix(self, func_index, str_index):
        if len(self._symbol_table) < default_check_count:
            count = len(self._symbol_table)
        else:
            count = default_check_count
        for i in range(count):
            if (func_index >= len(self._symbol_table)) or (str_index >= len(self._string_table)):
                return False
            if i == count - 1:
                return True
            if self._string_table[str_index]['length'] == self._symbol_table[func_index]['length']:
                func_index += 1
                str_index += 1
                continue
            else:
                return False

    def find_loading_address(self):
        self.prepare()
        if self._has_symbol is False:
            return None
        offset = 0
        while offset < len(self._firmware):
            self.logger.info('offset is : %s' % offset)
            str_start_address, str_end_address = self.find_string_table(offset)
            if str_start_address is None:
                break
            self.logger.info("Start get all strings from %s to %s" % (hex(str_start_address), hex(str_end_address)))
            self.get_string_table(str_start_address, str_end_address)
            # TODO: 需要性能优化
            self.logger.info("Start analyse")
            for func_index in range(len(self._symbol_table)):
                for str_index in range(len(self._string_table)):
                    if self._string_table[str_index]['length'] == self._symbol_table[func_index]['length']:
                        if self._check_fix(func_index, str_index) is True:
                            self.logger.info(self._symbol_table[func_index]['string_addr'])
                            self.logger.info(self._string_table[str_index]['address'])
                            self.load_address = int(self._symbol_table[func_index][
                                                         'string_addr'], 16) - int(
                                self._string_table[str_index]['address'], 16)
                            self.logger.info('load address is :%s' % hex(self.load_address))
                            return self.load_address
                    else:
                        continue
            self.logger.info('did not found loading address this time')
            self.logger.info('start search next string table!')
            offset = str_end_address
            self.logger.info('offset is %s' % hex(offset))
        self.logger.error("we can't find load address in this firmware, sorry!")

    def _check_load_address(self, address):
        if not self._has_symbol:
            return False
        if len(self._symbol_table) > default_check_count:
            count = default_check_count
        else:
            count = len(self._symbol_table)
        for i in range(count):
            offset = int(self._symbol_table[i]['string_addr'], 16) - address
            if offset <= 0:
                return False
            # TODO: 方法需要完善，目前只是判断符号表中string指针是否为字符来判断并不可靠。
            string, str_start_address, str_end_address = self._get_string_data(offset)
            if str_start_address != offset:
                self.logger.info("strings at offset didn't match symbol table")
                return False
        self.logger.info('load address is :%s' % hex(address))
        return True

    def quick_test(self):
        self.prepare()
        if self._has_symbol is False:
            return None
        for address in known_address:
            if self._check_load_address(address):
                self.load_address = address
                break
            else:
                self.logger.info('load address is not:%s' % hex(address))

    def cleanup(self):
        self._endian = None
        self.symbol_table_start = None
        self.symbol_table_end = None
        self._string_table = []
        self._symbol_table = []
        self.load_address = None
        self._has_symbol = None


#############plugin#################
class AutoFixIDBForm(idaapi.Form):
    def __init__(self):
        self.invert = False
        self.vx_version = 5
        super(AutoFixIDBForm, self).__init__(
            r"""BUTTON YES* Start analyze

VxHunter Auto Fix IDB will fix IDB with VxWorks symbol table.

Please choose VxWorks main version
{FormChangeCb}
<VxWorks Main Version     :{c_vxversion}>
            """, {
                'FormChangeCb': self.FormChangeCb(self.OnFormChange),
                'c_vxversion': self.DropdownListControl(
                    items=("5", "6"),
                    readonly=True,
                    selval=0),

            }
        )

        self.Compile()

    def OnFormChange(self, fid):
        if fid == -2:
            self.vx_version = (5, 6)[self.GetControlValue(self.c_vxversion)]
            return 1


# --------------------------------------------------------------------------
# Plugin
# --------------------------------------------------------------------------
class VxHunter_Plugin_t(idaapi.plugin_t):
    comment = "VxHunter plugin for IDA Pro (using Keystone framework)"
    help = ""
    wanted_name = "VxHunter"
    wanted_hotkey = ""
    flags = idaapi.PLUGIN_KEEP

    def init(self):
        # register popup menu handlers
        try:
            VxHunter_MC_Fix_IDB.register(self, "Auto Fix IDB")

        except:
            pass

        # setup popup menu
        if idaapi.IDA_SDK_VERSION >= 700:
            # Add menu IDA >= 7.0
            idaapi.attach_action_to_menu("Edit/VxHunter/Auto Fix IDB",
                                         VxHunter_MC_Fix_IDB.get_name(), idaapi.SETMENU_APP)
        else:
            # add Keypatch menu
            menu = idaapi.add_menu_item("Edit/VxHunter/", "Auto Fix IDB", "", 1, self.auto_fix_idb, None)
            if menu is not None:
                pass
            elif idaapi.IDA_SDK_VERSION < 680:
                # older IDAPython (such as in IDAPro 6.6) does add new submenu.
                # in this case, put VxHunter menu in menu Edit \ Patch program
                # not sure about v6.7, so to be safe we just check against v6.8
                idaapi.add_menu_item("Edit/Patch program/", "-", "", 0, self.menu_null, None)
                idaapi.add_menu_item("Edit/Patch program/", "VxHunter:: Auto Fix IDB", "", 0,
                                     self.auto_fix_idb, None)
        print("=" * 80)
        return idaapi.PLUGIN_KEEP

    def term(self):
        pass

    # null handler
    def menu_null(self):
        pass

    def auto_fix_idb(self):
        f = AutoFixIDBForm()
        ok = f.Execute()
        if ok == 1:
            vx_version = int(f.vx_version)
            print("vx_version:%s" % vx_version)
            firmware_path = idaapi.get_input_file_path()
            firmware = open(firmware_path).read()
            target = VxTarget(firmware=firmware, vx_version=vx_version)
            target.quick_test()
            if target.load_address:
                print("Load Address is:%s" % target.load_address)
            else:
                target.find_loading_address()
                if target.load_address:
                    print("Load Address is:%s" % target.load_address)
            if not target.load_address:
                return
            symbol_table_start = target.symbol_table_start
            symbol_table_end = target.symbol_table_end
            load_address = target.load_address
            self.fix_vxworks_idb(load_address, vx_version, symbol_table_start, symbol_table_end)
        f.Free()

    @staticmethod
    def fix_vxworks_idb(load_address, vx_version, symbol_table_start, symbol_table_end):
        current_image_base = idaapi.get_imagebase()
        symbol_interval = 16
        if vx_version == 6:
            symbol_interval = 20
        symbol_table_start += load_address
        symbol_table_end += load_address
        ea = symbol_table_start
        shift_address = load_address - current_image_base
        while shift_address >= 0x70000000:
            idaapi.rebase_program(0x70000000, 0x0008)
            shift_address -= 0x70000000
        idaapi.rebase_program(shift_address, 0x0008)
        # idaapi.autoWait()
        while ea < symbol_table_end:
            # for VxWorks 6 unknown symbol format
            if idc.Byte(ea + symbol_table_end - 2) == 3:
                ea += symbol_interval
                continue
            offset = 4
            if idaapi.IDA_SDK_VERSION >= 700:
                idc.create_strlit(idc.Dword(ea + offset), idc.BADADDR)
            else:
                idc.MakeStr(idc.Dword(ea + offset), idc.BADADDR)
            sName = idc.GetString(idc.Dword(ea + offset), -1, idc.ASCSTR_C)
            print(sName)
            if sName:
                eaFunc = idc.Dword(ea + offset + 4)
                idc.MakeName(eaFunc, sName)
                idc.MakeCode(eaFunc)
                idc.MakeFunction(eaFunc, idc.BADADDR)
            ea += symbol_interval
        idaapi.autoWait()

    def run(self, arg):
        self.auto_fix_idb()


try:
    class VxHunter_Menu_Context(idaapi.action_handler_t):

        @classmethod
        def get_name(self):
            return self.__name__

        @classmethod
        def get_label(self):
            return self.label

        @classmethod
        def register(self, plugin, label):
            self.plugin = plugin
            self.label = label
            instance = self()
            return idaapi.register_action(idaapi.action_desc_t(
                self.get_name(),  # Name. Acts as an ID. Must be unique.
                instance.get_label(),  # Label. That's what users see.
                instance  # Handler. Called when activated, and for updating
            ))

        @classmethod
        def unregister(self):
            """Unregister the action.
            After unregistering the class cannot be used.
            """
            idaapi.unregister_action(self.get_name())

        @classmethod
        def activate(self, ctx):
            # dummy method
            return 1

        @classmethod
        def update(self, ctx):
            try:
                if ctx.form_type == idaapi.BWN_DISASM:
                    return idaapi.AST_ENABLE_FOR_FORM
                else:
                    return idaapi.AST_DISABLE_FOR_FORM
            except:
                # Add exception for main menu on >= IDA 7.0
                return idaapi.AST_ENABLE_ALWAYS

    # context menu for Fix idb
    class VxHunter_MC_Fix_IDB(VxHunter_Menu_Context):
        def activate(self, ctx):
            self.plugin.auto_fix_idb()
            return 1

except:
    pass


# register IDA plugin
def PLUGIN_ENTRY():
    return VxHunter_Plugin_t()



