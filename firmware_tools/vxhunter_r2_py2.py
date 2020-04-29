# !/usr/bin/env python
# coding=utf-8
import logging
import struct
import r2pipe
import sys
from difflib import SequenceMatcher

default_check_count = 100

known_address = [0x80002000, 0x10000, 0x1000, 0xf2003fe4, 0x100000, 0x107fe0]

function_name_key_words = ['bzero', 'usrInit', 'bfill']

# VxWorks 5.5
vx_5_sym_types = [
    # 0x00,      # Undefined Symbol
    # 0x01,      # Global (external)
    # 0x02,      # Local Absolute
    0x03,      # Global Absolute
    0x04,      # Local .text
    0x05,      # Global .text
    0x06,      # Local Data
    0x07,      # Global Data
    0x08,      # Local BSS
    0x09,      # Global BSS
    0x12,      # Local Common symbol
    0x13,      # Global Common symbol
    0x40,      # Local Symbols related to a PowerPC SDA section
    0x41,      # Global Symbols related to a PowerPC SDA section
    0x80,      # Local symbols related to a PowerPC SDA2 section
    0x81,      # Local symbols related to a PowerPC SDA2 section
]

# VxWorks 6.8
vx_6_sym_types = [
    # 0x00,  # Undefined Symbol
    # 0x01,  # Global (external)
    # 0x02,  # Local Absolute
    0x03,  # Global Absolute
    0x04,  # Local .text
    0x05,  # Global .text
    0x08,  # Local Data
    0x09,  # Global Data
    0x10,  # Local BSS
    0x11,  # Global BSS
    0x20,  # Local Common symbol
    0x21,  # Global Common symbol
    0x40,  # Local Symbols
    0x41,  # Global Symbols
]

need_create_function = [
    0x04,
    0x05
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
        self.symbols = []
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
        check_data = self._firmware[offset:offset + self._symbol_interval * default_check_count]
        is_big_endian = True
        is_little_endian = True
        # check symbol data match struct
        for i in range(default_check_count):
            check_data_1 = check_data[i * self._symbol_interval:(i + 1) * self._symbol_interval]
            if len(check_data_1) < self._symbol_interval:
                self.logger.debug("check_data_1 length is too small")
                break

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
            # Check symbol type is valid
            sym_type = ord(data[14])
            if sym_type not in vx_5_sym_types:
                return False

            # symbol should end with '\x00'
            if data[15] != '\x00':
                return False

            # Check symbol group is '\x00\x00'
            if data[12:14] != '\x00\x00':
                return False

            # symbol_name point should not be zero
            if data[4:8] == '\x00\x00\x00\x00':
                return False

            # symbol value point should not be zero
            if data[8:12] == '\x00\x00\x00\x00':
                return False

            return True

        elif self._vx_version == 6:
            # Check symbol type is valid
            sym_type = ord(data[18])
            if sym_type not in vx_6_sym_types:
                return False

            # symbol should end with '\x00'
            if data[19] != '\x00':
                return False

            # Check symbol group is '\x00\x00'
            if data[16:18] != '\x00\x00':
                return False

            # symbol_name point should not be zero
            if data[4:8] == '\x00\x00\x00\x00':
                return False

            # TODO: Need handle this problem
            # sometime data[8:12] will be '\x00\x00\x00\x00'
            # if data[8:12] == '\x00\x00\x00\x00':
            #     return False
            return True

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

                if len(check_data) < self._symbol_interval:
                    self.logger.debug("Check_data length is too small")
                    break

                if self._check_symbol_format_simple(check_data):
                    self.symbol_table_end = i + self._symbol_interval
                    self.logger.debug("self.symbol_table_end: {:010x}".format(self.symbol_table_end))

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
            symbol_flag = ord(self._firmware[i + self._symbol_interval - 2])
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
                'symbol_flag': symbol_flag,
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

        self.logger.info("Start analyse")

        temp_symbol_table = list(map(lambda x: x['symbol_name_length'], self._symbol_table))
        temp_string_table = list(map(lambda x: x['length'], self._string_table))
        matcher = SequenceMatcher(None, temp_symbol_table, temp_string_table)
        func_index, str_index, length = matcher.find_longest_match(0, len(temp_symbol_table), 0, len(temp_string_table))
        if length >= default_check_count:
            self.load_address = self._symbol_table[func_index]['symbol_name_addr'] - \
                                self._string_table[str_index]['address']
            return self.load_address

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

    def get_string_from_firmware_by_offset(self, string_offset):
        symbol_name = ""
        while True:
            if self._firmware[string_offset] != '\x00':
                symbol_name += self._firmware[string_offset]
                string_offset += 1

            else:
                break

        return symbol_name

    def get_symbols(self):
        self.symbols = []
        if self.load_address:
            for symbol in self._symbol_table:
                symbol_name_addr = symbol["symbol_name_addr"]
                symbol_dest_addr = symbol["symbol_dest_addr"]
                symbol_flag = symbol["symbol_flag"]
                symbol_name_firmware_addr = symbol_name_addr - self.load_address
                symbol_name = self.get_string_from_firmware_by_offset(symbol_name_firmware_addr)
                self.symbols.append({
                    "symbol_name": symbol_name,
                    "symbol_name_addr": symbol_name_addr,
                    "symbol_dest_addr": symbol_dest_addr,
                    "symbol_flag": symbol_flag
                })
            return self.symbols

        else:
            return None


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


def autodetect_vxworks_version(r2p):
    ''' Naive way to autodetect VxWorks version '''
    vx_version = None
    # TODO: replace with cmdj and izzzj later, currently izzzj is not stable.
    vx_version_r2p = r2p.cmd("izz~VxWorks")
    if 'VxWorks5' in vx_version_r2p:
        vx_version = 5

    elif 'VxWorks6' in vx_version_r2p:
        vx_version = 6

    return vx_version


def manual_vxworks_version():
    while True:
        vx_version = input("Please input the VxWorks main version type 'c' to exit\nAvailable (5/6/c): ")
        if str(vx_version) == "5":
            vx_version = 5
            return vx_version

        elif str(vx_version) == "6":
            vx_version = 6
            return vx_version

        elif str(vx_version).lower() == "c":
            sys.exit()

        else:
            return None


def add_symbol(symbol_name, symbol_name_address, symbol_address, symbol_type):
    # Load symbols
    if symbol_name:
        if symbol_type in need_create_function:
            r2_command = "fs functions; f {} @ 0x{:08X}".format(symbol_name, symbol_address)
            r2p.cmd(r2_command)
            # TODO: Need find a way to disable warnning "af: Cannot find function at"
            r2_command = "af {} 0x{:08X}".format(symbol_name, symbol_address)
            r2p.cmd(r2_command)

        else:
            r2_command = "fs symbols; f {} @ 0x{:08X}".format(symbol_name, symbol_address)
            r2p.cmd(r2_command)

    return


def get_r2_opened_file(r2_opened_file_data):
    for opened_file in r2_opened_file_data:
        if isinstance(opened_file, dict):
            if opened_file["raised"] is True and not opened_file["uri"].lower().startswith("malloc"):
                return opened_file["uri"]

    return None


if __name__ == '__main__':
    print("Running with python version: {}".format(sys.version))
    r2p = r2pipe.open()
    vx_version = None
    if len(sys.argv) == 2:
        vx_version = str(sys.argv[1])
        if str(vx_version) == "5":
            vx_version = 5
            print("vx_version:{}".format(vx_version))
        elif str(vx_version) == "6":
            vx_version = 6
            print("vx_version:{}".format(vx_version))
        else:
            vx_version = None

    if vx_version is None:
        vx_version = autodetect_vxworks_version(r2p)
        print("Auto detected VxWorks version: {}".format(vx_version))

    if vx_version is None:
        vx_version = manual_vxworks_version()
        print("vx_version:{}".format(vx_version))

    # only use first file
    opened_file_data = r2p.cmdj("oj*")
    firmware_path = get_r2_opened_file(opened_file_data)
    if firmware_path is None:
        print("Can't get firmware_path, exit.")
        sys.exit()
    print("firmware_path: {}".format(firmware_path))

    firmware = open(firmware_path, 'rb').read()
    target = VxTarget(firmware=firmware, vx_version=vx_version)
    # target.logger.setLevel(logging.DEBUG)
    print("\n###### Start analyze firmware ######")
    target.quick_test()
    if target.load_address is None:
        target.find_loading_address()
    if target.load_address is None:
        print("Can't find image load address, exit.")
        sys.exit()

    image_load_address = target.load_address
    symbol_table_start_address = target.symbol_table_start
    symbol_table_end_address = target.symbol_table_end
    print("Found VxWorks image load address: 0x{:08X}".format(image_load_address))
    print("Found VxWorks symbol table from 0x{:08X} to 0x{:08X}".format(symbol_table_start_address,
                                                                        symbol_table_end_address))


    ##################
    # Rebase program #
    ##################
    print("\n###### Rebase current firmware ######")
    # close all open files
    r2p.cmd("o--")
    # backup current asm bits
    current_conf = r2p.cmdj("ej")
    current_asm_bits = current_conf['asm.bits']
    # map image to correct load address
    r2_command = "o {} {} r-x".format(firmware_path, hex(image_load_address))
    print("Rebase with r2 command: {}".format(r2_command))
    r2p.cmd(r2_command)
    # recover asm bits setup
    r2_command = "e asm.bits={}".format(current_asm_bits)
    r2p.cmd(r2_command)

    ####################
    # Create Functions #
    ####################
    # Check endian
    print("\n###### Start analyzing functions######")
    if target.big_endian:
        r2p.cmd("e cfg.bigendian=True")

    symbols = target.get_symbols()
    for symbol in symbols:
        try:
            symbol_name = symbol["symbol_name"]
            symbol_name_addr = symbol["symbol_name_addr"]
            symbol_dest_addr = symbol["symbol_dest_addr"]
            symbol_type = symbol["symbol_flag"]
            add_symbol(symbol_name, symbol_name_addr, symbol_dest_addr, symbol_type)

        except Exception as err:
            continue

    flags = r2p.cmdj("fsj")
    function_count = 0
    symbol_count = 0
    for flag in flags:
        if flag['name'] == "functions":
            function_count = flag["count"]
        elif flag['name'] == "symbols":
            symbol_count = flag["count"]

    r2_command = "?E3 Finished, VxHunter found {} functions and {} symbols ^_^".format(function_count, symbol_count)
    print("\n{}".format(r2p.cmd(r2_command)))
