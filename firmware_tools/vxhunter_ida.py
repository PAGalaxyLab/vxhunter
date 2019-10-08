# coding=utf-8
import logging
import struct
import idc
import idaapi


default_check_count = 100

known_address = [0x80002000, 0x10000, 0x1000, 0xf2003fe4, 0x100000, 0x107fe0]

function_name_key_words = ['bzero', 'usrInit', 'bfill']

symbol_format_sign_5 = [
    '\x00\x00\x05\x00',  # Function
    '\x00\x00\x07\x00',  # Variable
    '\x00\x00\x09\x00',  # Variable
    '\x00\x00\x11\x00'   #
]

symbol_format_sign_6 = [
    '\x00\x00\x00\x00\x00\x00\x03\x00',  # Unknown Type (Might not function name)
    '\x00\x00\x00\x00\x00\x00\x05\x00',  # Function
    '\x00\x00\x00\x00\x00\x00\x07\x00',  # Variable
    '\x00\x00\x00\x00\x00\x00\x09\x00',  # Variable
    '\x00\x00\x00\x00\x00\x00\x11\x00'
]

sym_flags = [
    0,      # Undefined Symbol
    2,      # Local Absolute
    3,      # Global Absolute
    4,      # Local .text
    5,      # Global .text
    6,      # Local Data
    7,      # Global Data
    8,      # Local BSS
    9,      # Global BSS
]

need_create_function = [
    0x0500,
    0x050000
]


class VxTarget(object):
    def __init__(self, firmware, vx_version=5, big_endian=False, logger=None):
        """
        :param firmware: data of firmware
        :param vx_version: 5 = VxWorks 5.x; 6= VxWorks 6.x
        :param big_endian: True = big endian; False = little endian
        :param logger: logger for the target (default: None)
        """
        self.big_endian = big_endian
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
        self.prepare()

    def prepare(self):
        """ Trying to find symbol from image.

        :return: True if found symbol, False otherwise.
        """
        self.find_symbol_table()
        if self._has_symbol is False:
            return None
        self.logger.debug("has_symbol: %s" % self._has_symbol)
        self.get_symbol_table()

    def _check_vxworks_endian(self):
        """ Get image endian from image file.

        :return:
        """
        data1 = self._firmware[self.symbol_table_start + 4:self.symbol_table_start + 4 + self._symbol_interval]
        data2 = self._firmware[self.symbol_table_start + 4 + self._symbol_interval:self.symbol_table_start +
                                                                                   4 + self._symbol_interval * 2]
        if data1[0:2] == data2[0:2]:
            self.logger.info("VxWorks endian: Big endian")
            self.big_endian = True
        elif data1[2:4] == data2[2:4]:
            self.logger.info("VxWorks endian: Little endian")
            self.big_endian = False
        else:
            self.logger.info("VxWorks endian: Little endian")
            self.big_endian = False

    def _check_symbol_format(self, offset):
        """ Check offset is symbol table.

        :param offset: offset from image.
        :return: True if offset is symbol table, False otherwise.
        """
        check_data = self._firmware[offset:offset + self._symbol_interval * 10]
        is_big_endian = True
        is_little_endian = True
        # check symbol data match sign
        for i in range(10):
            check_data_1 = check_data[i * self._symbol_interval:(i + 1) * self._symbol_interval]
            if self._check_symbol_format_simple(check_data_1) is False:
                return False

        if self._vx_version == 5:
            self.logger.debug("Check VxWorks 5 symbol format")
            # check is big endian
            for i in range(9):
                check_data_1 = check_data[4 + i * self._symbol_interval:6 + i * self._symbol_interval]
                data2 = check_data[4 + (i + 1) * self._symbol_interval:6 + (i + 1) * self._symbol_interval]
                if check_data_1 != data2:
                    self.logger.debug("is not big endian")
                    is_big_endian = False
                    break

            # check is little endian
            for i in range(9):
                check_data_1 = check_data[6 + i * self._symbol_interval:8 + i * self._symbol_interval]
                data2 = check_data[6 + (i + 1) * self._symbol_interval:8 + (i + 1) * self._symbol_interval]
                if check_data_1 != data2:
                    self.logger.debug("is not little endian")
                    is_little_endian = False
                    break

            return is_big_endian ^ is_little_endian

        return True

    def _check_symbol_format_simple(self, data):
        """ Check single symbol format is correct.

        :param data: single symbol data.
        :return: True if data is symbol, False otherwise.
        """
        if self._vx_version == 5:
            if data[:4] != '\x00\x00\x00\x00':
                return False
            if data[4:8] == '\x00\x00\x00\x00':
                return False
            if data[8:12] == '\x00\x00\x00\x00':
                return False
            for sign in symbol_format_sign_5:
                if data[-4:] == sign:
                    return True
            return False

        elif self._vx_version == 6:
            if data[:4] != '\x00\x00\x00\x00':
                return False
            if data[4:8] == '\x00\x00\x00\x00':
                return False
            # TODO: Need handle this problem
            # sometime data[8:12] will be '\x00\x00\x00\x00'
            # if data[8:12] == '\x00\x00\x00\x00':
            #     return False
            if data[-8:] in symbol_format_sign_6:
                return True
            return False

        return False

    def find_symbol_table(self):
        """ Find symbol table from image.

        :return:
        """
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
                check_data = self._firmware[i:i + self._symbol_interval]
                if self._check_symbol_format_simple(check_data):
                    self.symbol_table_end = i + self._symbol_interval
                else:
                    self.logger.info("symbol table end offset: %s" % hex(self.symbol_table_end))
                    break
        else:
            self.logger.error("didn't find symbol table in this image")
            self._has_symbol = False

    def get_symbol_table(self):
        """ get symbol table data.

        :return: True if get symbol table data successful, False otherwise.
        """
        if self.symbol_table_start and self.symbol_table_end:
            self._check_vxworks_endian()

        else:
            return False

        for i in range(self.symbol_table_start, self.symbol_table_end, self._symbol_interval):
            symbol_name_addr = self._firmware[i + 4:i + 8]
            symbol_dest_addr = self._firmware[i + 8:i + 12]
            if self.big_endian:
                unpack_format = '>I'
            else:
                unpack_format = '<I'
            symbol_name_addr = int(struct.unpack(unpack_format, symbol_name_addr)[0])
            self.logger.debug("symbol_name_addr: %s" % symbol_name_addr)
            symbol_dest_addr = int(struct.unpack(unpack_format, symbol_dest_addr)[0])
            self.logger.debug("symbol_dest_addr: %s" % symbol_dest_addr)
            self._symbol_table.append({
                'symbol_name_addr': symbol_name_addr,
                'symbol_name_length': None,
                'symbol_dest_addr': symbol_dest_addr,
                'offset': i
            })
        # self.logger.debug("self._symbol_table: %s" % self._symbol_table)
        self.logger.debug("len(self._symbol_table): %s".format(len(self._symbol_table)))
        self._symbol_table = sorted(self._symbol_table, key=lambda x: x['symbol_name_addr'])
        for i in range(len(self._symbol_table) - 1):
            self._symbol_table[i]['symbol_name_length'] = self._symbol_table[i + 1]['symbol_name_addr'] - \
                                                        self._symbol_table[i]['symbol_name_addr']
        self.logger.debug("len(self._symbol_table): %s".format(len(self._symbol_table)))
        return True

    @staticmethod
    def _is_printable(c):
        """ Check Char is printable.

        :param c: char to check.
        :return: True if char is printable, False otherwise.
        """
        return 32 <= ord(c) <= 126

    def _check_is_func_name(self, string):
        """ Check target string is match function name format.

        :param string: string to check.
        :return: True if string is match function name format, False otherwise.
        """
        #
        bad_str = ['\\', '%', '+', ',', '&', '/', ')', '(', '[', ']']
        # function name length should less than 512 byte
        if len(string) > 512:
            return False

        for data in bad_str:
            if data in string:
                return False

        for c in string:
            if self._is_printable(c) is False:
                return False
        return True

    def _get_prev_string_data(self, offset):
        """ Get previous string from giving offset.

        :param offset: offset of image.
        :return: string data, string start offset, string end offset.
        """
        while offset > 0:
            if self._firmware[offset].encode('hex') != '00':
                start_address = offset
                end_address = offset + 1
                while offset > 0:
                    if self._firmware[offset - 1].encode('hex') == '00':
                        start_address = offset
                        break
                    offset -= 1
                data = self._firmware[start_address:end_address]
                return data, start_address, end_address
            else:
                offset -= 1
        return None, None, None

    def _get_next_string_data(self, offset):
        """ Get next string from giving offset.

        :param offset: offset of image.
        :return: string data, string start offset, string end offset.
        """
        while offset < len(self._firmware):
            if self._firmware[offset] != '\x00':
                start_address = offset
                end_address = offset
                while offset <= len(self._firmware):
                    offset += 1
                    if self._firmware[offset] == '\x00':
                        end_address = offset
                        break
                data = self._firmware[start_address:end_address]
                return data, start_address, end_address
            else:
                offset += 1
        return None, None, None

    def find_string_table_by_key_function_index(self, key_offset):
        """ Find string table by VxWorks key function name offset in VxWorks image.

        :param key_offset: key function name offset in VxWorks image.
        :return:
        """
        temp_str_tab_data = []
        if len(self._symbol_table) > default_check_count:
            count = default_check_count
        else:
            count = len(self._symbol_table)
        start_offset = key_offset
        end_offset = key_offset

        while start_offset > 0:
            if self._is_printable(self._firmware[start_offset]) is True:
                # get string from offset
                string, start_address, end_address = self._get_prev_string_data(start_offset)
                self.logger.debug("string:%s, start_address:%s, end_address:%s" % (string, hex(start_address), hex(end_address)))
                # check string is function name
                if self._check_is_func_name(string) is False:
                    if len(temp_str_tab_data) < count:
                        self.logger.error("Can't find any string table with key index.")
                        return None, None
                    else:
                        self.logger.info("found string table start address at %s" % hex(start_address))
                        break
                else:
                    temp_str_tab_data.append((string, start_address, end_address))

                # get previous string from offset
                prev_string, prev_start_address, prev_end_address = self._get_prev_string_data(start_address - 1)
                self.logger.debug(
                    "prev_string:%s, prev_start_address:%s, prev_end_address:%s" % (prev_string, hex(prev_start_address), hex(prev_end_address)))
                if prev_start_address:
                    # strings interval should less than 4
                    if 4 < (start_address - prev_end_address):
                        if len(temp_str_tab_data) < count:
                            self.logger.error("Can't find any string table with key index.")
                            return None, None
                        else:
                            self.logger.info("found string table start address at %s" % hex(start_address))
                            break
                    else:
                        start_offset = start_address - 1
                        self.logger.debug("start_offset: %s" % start_offset)
                else:
                    break
            else:
                start_offset -= 1

        while end_offset < len(self._firmware):
            # find first printable char
            if self._is_printable(self._firmware[end_offset]) is True:
                # get string from offset
                string, start_address, end_address = self._get_next_string_data(end_offset)
                # check string is function name
                if self._check_is_func_name(string) is False:
                    if len(temp_str_tab_data) < count:
                        temp_str_tab_data = []
                        end_offset = end_address
                        continue
                    else:
                        self.logger.info("found string table end at %s" % hex(end_address))
                        break
                        # start_offset = temp_str_tab_data[0][1]
                        # end_offset = temp_str_tab_data[-1][2]
                else:
                    temp_str_tab_data.append((string, start_address, end_address))

                # get next string from offset
                next_string, next_start_address, next_end_address = self._get_next_string_data(end_address)
                if next_start_address:
                    # strings interval should less than 4
                    if 4 < (next_start_address - end_address):
                        if len(temp_str_tab_data) < count:
                            self.logger.error("Can't find any string table with key index.")
                            return None, None
                        else:
                            self.logger.info("found string table end at %s" % hex(end_address))
                            break
                    else:
                        end_offset = end_address
            else:
                end_offset += 1

        temp_str_tab_data = sorted(temp_str_tab_data, key=lambda x: (x[1]))
        table_start_offset = temp_str_tab_data[0][1]
        table_end_offset = temp_str_tab_data[-1][2]
        self.logger.info("found a string tab at: %s to %s" % (hex(table_start_offset), hex(table_end_offset)))
        return table_start_offset, table_end_offset

    def get_string_table(self, str_start_address, str_end_address):
        """ Get string table data from VxWorks image with string table start and end offset.

        :param str_start_address: string table start address.
        :param str_end_address: string table end address.
        :return:
        """
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
                            'address': address,
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
        """

        :param func_index:
        :param str_index:
        :return:
        """
        fault_count = 0

        if len(self._symbol_table) < default_check_count:
            count = len(self._symbol_table)
        else:
            count = default_check_count
        for i in range(count):
            self.logger.debug("str_index: {}".format(str_index))
            self.logger.debug("self._string_table[str_index]: {}".format(self._string_table[str_index]))
            self.logger.debug("func_index: {}".format(func_index))
            self.logger.debug("self._symbol_table[func_index]: {}".format(self._symbol_table[func_index]))

            if (func_index >= len(self._symbol_table)) or (str_index >= len(self._string_table)):
                self.logger.debug("_check_fix False")
                return False
            if i == count - 1:
                if fault_count < 10:
                    self.logger.debug("_check_fix True")
                    return True
                else:
                    self.logger.debug("_check_fix False too many fault")
                    return False

            if self._string_table[str_index]['length'] == self._symbol_table[func_index]['symbol_name_length']:
                func_index += 1
                str_index += 1
                self.logger.debug("_check_fix continue")

            elif self._symbol_table[func_index]['symbol_name_length'] < self._string_table[str_index]['length']:
                # Sometime Symbol name might point to mid of string.
                fault_count += 1
                func_index += 1
            else:
                self.logger.debug("_check_fix False2")
                return False

    def find_loading_address(self):
        """ Find VxWorks image load address by automatic analysis.

        :return: Load address if found, None otherwise.
        """
        if self._has_symbol is False:
            return None

        for key_word in function_name_key_words:
            prefix_keyword = '\x00_' + key_word + '\x00'
            key_word = '\x00' + key_word + '\x00'
            if key_word in self._firmware is False and prefix_keyword in self._firmware is False:
                self.logger.info("This firmware didn't contain function name")
                return None
        try:
            key_function_index = self._firmware.index('\x00' + function_name_key_words[0] + '\x00')
        except Exception as err:
            # Handler _ prefix symbols
            key_function_index = self._firmware.index('\x00_' + function_name_key_words[0] + '\x00')

        str_start_address, str_end_address = self.find_string_table_by_key_function_index(key_function_index)
        self.get_string_table(str_start_address, str_end_address)
        # TODO: Need improve performance
        self.logger.info("Start analyse")
        for str_index in range(len(self._string_table)):
            for func_index in range(len(self._symbol_table)):
                self.logger.debug(
                    "self._string_table[str_index]['length']: %s" % self._string_table[str_index]['length'])
                self.logger.debug(
                    "self._symbol_table[func_index]['symbol_name_length']: %s" % self._symbol_table[func_index][
                        'symbol_name_length'])
                if self._string_table[str_index]['length'] == self._symbol_table[func_index]['symbol_name_length']:
                    if self._check_fix(func_index, str_index) is True:
                        self.logger.debug("self._symbol_table[func_index]['symbol_name_addr']: %s" % self._symbol_table[func_index]['symbol_name_addr'])
                        self.logger.debug("self._string_table[str_index]['address']: %s" % self._string_table[str_index]['address'])
                        self.load_address = self._symbol_table[func_index]['symbol_name_addr'] - \
                                            self._string_table[str_index]['address']
                        self.logger.info('load address is :%s' % hex(self.load_address))
                        return self.load_address
                else:
                    continue
        self.logger.error("We didn't find load address in this firmware, sorry!")

    def _check_load_address(self, address):
        """

        :param address:
        :return:
        """
        if not self._has_symbol:
            return False
        if len(self._symbol_table) > default_check_count:
            count = default_check_count
        else:
            count = len(self._symbol_table)
        self.logger.debug("symbol_table length is:%s" % count)
        for i in range(count):
            offset = self._symbol_table[i]['symbol_name_addr'] - address
            if offset <= 0:
                return False
            # TODO: Need improve, currently use string point to check.
            string, str_start_address, str_end_address = self._get_next_string_data(offset)
            if str_start_address != offset:
                self.logger.info("strings at offset didn't match symbol table")
                return False
        self.logger.info('load address is :%s' % hex(address))
        return True

    def quick_test(self):
        """ Using known load address list to match VxWorks image.

        :return: Load address if match known address, None otherwise.
        """
        if self._has_symbol is False:
            return None
        self.logger.debug("has_symbol: %s" % self._has_symbol)
        for address in known_address:
            if self._check_load_address(address):
                self.load_address = address
                return self.load_address
            else:
                self.logger.info('load address is not:%s' % hex(address))

    def cleanup(self):
        """ Clean up variables.

        :return:
        """
        self.big_endian = False
        self.symbol_table_start = None
        self.symbol_table_end = None
        self._string_table = []
        self._symbol_table = []
        self.load_address = None
        self._has_symbol = None


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



# --------------------------------------------------------------------------
# Plugin
# --------------------------------------------------------------------------
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


class FixCodeForm(idaapi.Form):
    def __init__(self):
        self.invert = False
        self.start_address = 0
        self.end_address = 0
        super(FixCodeForm, self).__init__(
            r"""BUTTON YES* Fix Code from image

VxHunter fix code will make all data as code from start_address to end_address. 

Please input start address and end address
{FormChangeCb}
<Start address     :{c_StartAddress}>
<End address     :{c_EndAddress}>
            """, {
                'FormChangeCb': self.FormChangeCb(self.OnFormChange),
                'c_StartAddress': self.NumericInput(value=self.start_address, swidth=40, tp=self.FT_ADDR),
                'c_EndAddress': self.NumericInput(value=self.end_address, swidth=40, tp=self.FT_ADDR),
            }
        )
        self.Compile()

    def OnFormChange(self, fid):
        if fid == -2:
            self.start_address = self.GetControlValue(self.c_StartAddress)
            self.end_address = self.GetControlValue(self.c_EndAddress)
            return 1


class FixAsciiForm(idaapi.Form):
    def __init__(self):
        self.invert = False
        self.string_address = 0
        super(FixAsciiForm, self).__init__(
            r"""BUTTON YES* Fix Code from image

VxHunter fix ascii string. 

Please input string table start address.
{FormChangeCb}
<String Address     :{c_Address}>
            """, {
                'FormChangeCb': self.FormChangeCb(self.OnFormChange),
                'c_Address': self.NumericInput(value=self.string_address, swidth=40, tp=self.FT_ADDR),
            }
        )
        self.Compile()

    def OnFormChange(self, fid):
        if fid == -2:
            self.string_address = self.GetControlValue(self.c_Address)
            return 1


class VxHunter_Plugin_t(idaapi.plugin_t):
    comment = "VxHunter plugin for IDA Pro"
    help = ""
    wanted_name = "VxHunter"
    wanted_hotkey = ""
    flags = idaapi.PLUGIN_KEEP

    def init(self):
        # register popup menu handlers
        try:
            # Register Auto Fix IDB handler
            VxHunterMCFixIDB.register(self, "Auto Fix IDB With symbol table")
            # Register Fix Code handler
            VxHunterMCFixCode.register(self, "Fix Code from start address to end address")
            # Register Fix Ascii handler
            VxHunterMCFixAscii.register(self, "Fix Ascii string table with giving address")

        except Exception as err:
            print("Got Error!!!: %s" % err)

        # setup popup menu
        if idaapi.IDA_SDK_VERSION >= 700:
            # Add menu IDA >= 7.0
            idaapi.attach_action_to_menu("Edit/VxHunter/", VxHunterMCFixIDB.get_name(), idaapi.SETMENU_APP)
            idaapi.attach_action_to_menu("Edit/VxHunter/", VxHunterMCFixCode.get_name(), idaapi.SETMENU_APP)
            idaapi.attach_action_to_menu("Edit/VxHunter/", VxHunterMCFixAscii.get_name(), idaapi.SETMENU_APP)
        else:
            # add Vxhunter menu
            menu = idaapi.add_menu_item("Edit/VxHunter/", "Auto Fix IDB1", "", 1, self.handler_auto_fix_idb, None)
            if menu is not None:
                pass

        print("=" * 80)
        return idaapi.PLUGIN_KEEP

    def term(self):
        pass

    # null handler
    def menu_null(self):
        pass

    def handler_auto_fix_idb(self):
        form = AutoFixIDBForm()
        ok = form.Execute()
        if ok == 1:
            vx_version = int(form.vx_version)
            print("vx_version:%s" % vx_version)
            firmware_path = idaapi.get_input_file_path()
            firmware = open(firmware_path).read()
            target = VxTarget(firmware=firmware, vx_version=vx_version)
            # target.logger.setLevel(logging.DEBUG)
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
        form.Free()

    def handler_fix_code(self):
        form = FixCodeForm()
        ok = form.Execute()
        if ok == 1:
            start_address = int(form.start_address)
            end_address = int(form.end_address)
            self.fix_code(start_address, end_address)
        form.Free()

    def handler_fix_ascii(self):
        form = FixAsciiForm()
        ok = form.Execute()
        if ok == 1:
            string_address = int(form.string_address)
            self.fix_ascii(string_address)

        form.Free()

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
            print("Found %s in symbol table" % sName)
            if sName:
                sName_dst = idc.Dword(ea + offset + 4)
                if vx_version == 6:
                    sName_type = idc.Dword(ea + offset + 12)
                else:
                    sName_type = idc.Dword(ea + offset + 8)
                idc.MakeName(sName_dst, sName)
                if sName_type in need_create_function:
                    # flags = idc.GetFlags(ea)
                    print("Start fix Function %s at %s" % (sName, hex(sName_dst)))
                    idc.MakeCode(sName_dst)  # might not need
                    idc.MakeFunction(sName_dst, idc.BADADDR)
            ea += symbol_interval
        print("Fix function by symbol table finish.")
        print("Start IDA auto analysis, depending on the size of the firmware this might take a few minutes.")
        idaapi.autoWait()

    @staticmethod
    def fix_code(start_address, end_address):
        # Todo: There might be some data in the range of codes.
        offset = start_address
        while offset <= end_address:
            offset = idc.NextAddr(offset)
            flags = idc.GetFlags(offset)
            if not idc.isCode(flags):
                # Todo: Check should use MakeCode or MakeFunction
                # idc.MakeCode(offset)
                idc.MakeFunction(offset)

    @staticmethod
    def get_prev_ascii_string_address(address):
        """

        :param address: must be current ascii string start address.
        :return:
        """
        prev_string_start_address = address
        # string table interval should less than 5 bytes.
        if idc.Dword(address - 5) == 0:
            return None
        else:
            prev_string_start_address -= 5
            # TODO: Need handle short string.
            while idaapi.get_byte(prev_string_start_address) != 0:
                prev_string_start_address -= 1
            return prev_string_start_address + 1

    @staticmethod
    def get_next_ascii_string_address(address):
        """

        :param address: must be current ascii string start address.
        :return:
        """
        next_string_start_address = address
        # find current string end address
        while idaapi.get_byte(next_string_start_address) != 0:
            next_string_start_address += 1

        # string table interval should less than 5 bytes.
        # TODO: need handle short string.
        if idc.Dword(next_string_start_address + 1) == 0:
            return None

        while idaapi.get_byte(next_string_start_address) == 0:
            next_string_start_address += 1

        return next_string_start_address

    def get_string_table_start_address(self, address):
        string_table_start_address = address
        # find current string start address
        while idaapi.get_byte(string_table_start_address - 1) != 0:
            string_table_start_address -= 1

        while self.get_prev_ascii_string_address(string_table_start_address):
            string_table_start_address = self.get_prev_ascii_string_address(string_table_start_address)

        return string_table_start_address

    def fix_ascii(self, address):
        string_table_start_address = self.get_string_table_start_address(address)
        string_address = string_table_start_address
        while True:
            if string_address:
                print("Start Make string at address: %s" % hex(string_address))
                if idaapi.IDA_SDK_VERSION >= 700:
                    idc.create_strlit(string_address, idc.BADADDR)
                else:
                    idc.MakeStr(string_address, idc.BADADDR)
                string_address = self.get_next_ascii_string_address(string_address)
            else:
                break

    def run(self, arg):
        self.handler_auto_fix_idb()


try:
    class VxHunterMenuContext(idaapi.action_handler_t):

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
    class VxHunterMCFixIDB(VxHunterMenuContext):
        def activate(self, ctx):
            self.plugin.handler_auto_fix_idb()
            return 1

    class VxHunterMCFixCode(VxHunterMenuContext):
        def activate(self, ctx):
            self.plugin.handler_fix_code()
            return 1

    class VxHunterMCFixAscii(VxHunterMenuContext):
        def activate(self, ctx):
            self.plugin.handler_fix_ascii()
            return 1

except Exception as err:
    # TODO: Add some handle later.
    pass


# register IDA plugin
def PLUGIN_ENTRY():
    return VxHunter_Plugin_t()



