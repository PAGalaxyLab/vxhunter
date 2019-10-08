# coding=utf-8
import logging
import struct

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
