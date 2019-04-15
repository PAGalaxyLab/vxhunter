# !/usr/bin/env python2
# coding=utf-8
from serialtube import serialtube
import logging

# init serial
serial_port = "/dev/tty.usbserial-AI069JDS"

start_address = 0x80001000
length = 0x24ab00
interval = 0x100
dump_data = ''


class VxSerialBaseTarget(object):
    def __init__(self, serial=None, serial_until='\r\n#', logger=None):
        """ Base VxSerial Target, used to provide memory read/write functions.

        :param serial: serialtube object.
        :param logger: logger for the target (default: None)
        """
        if isinstance(serial, serialtube):
            self.serial = serial
        else:
            self.serial = None
        self.mem_cache_data = {}
        self.serial_until = serial_until
        if logger is None:
            self.logger = logging.getLogger('target')
            self.logger.setLevel(logging.INFO)
            console_handler = logging.StreamHandler()
            console_format = logging.Formatter('[%(levelname)-8s][%(module)s.%(funcName)s] %(message)s')
            console_handler.setFormatter(console_format)
            self.logger.addHandler(console_handler)
        else:
            self.logger = logger

    def setup_serial(self, serial_path, baudrate=115200, **kwargs):
        try:
            self.serial = serialtube(port=serial_path, baudrate=baudrate, **kwargs)

        except Exception as err:
            self.logger.error("Serial setup fail because of: {}".format(err))
            self.serial = None

    def check_serial_alive(self):
        if self.serial:
            return True
        self.logger.error("Please setup the serial port using setup_serial function first!")
        return False

    def send_and_recvuntil(self, data, until='\r\n#', timeout=3):
        """

        :param data: Data to send.
        :param until: Receive until characters (default: '\r\n#')
        :param timeout: Timeout.
        :return: Response Data
        """
        if not self.check_serial_alive():
            return None
        self.serial.sendlinethen(data="", delim=until, timeout=timeout)
        self.logger.debug("send data: %s" % data)
        rsp_data = self.serial.sendlinethen(data=data, delim=until, timeout=timeout)
        self.logger.debug("rsp_data: %s" % rsp_data)
        if data not in rsp_data:
            self.logger.debug('Target might crash, reset target cmd')
            self.reset_shell()
            return self.send_and_recvuntil(data, until)
        return rsp_data

    def reset_shell(self):
        """Used to reset target shell task.

        :return: None
        """
        if not self.check_serial_alive():
            return None
        self.serial.recvuntil('\r\n#', timeout=1)
        self.serial.send('03'.decode('hex'))  # Send ctrl + c to reset target shell.
        self.serial.recvuntil('\r\n#', timeout=3)

    def get_mem_data_from_dump(self, raw_data):
        '''Memory dump output parse, used to get raw memory dump data, need overwritten for specific target.

        :param raw_data: Memory dump command output.
        :return: Raw memory dump data.
        '''
        rsp_data = {}
        rsp_hex_data = ''
        data_list = raw_data.split('\r\n')
        self.logger.debug("data_list: %s" % data_list)
        # check address offset
        for data in data_list:
            try:
                self.logger.debug('data: %s' % data)
                address = int(data[:8], 16)
                self.logger.debug("address: %s" % hex(address))
                hex_data = data[11:60]
                hex_data = hex_data.replace(' ', '')
                hex_data = hex_data.replace('-', '')
                self.logger.debug("hex_data: %s" % hex_data)
                if len(hex_data) != 32:
                    self.logger.error('hex_data length format error!')
                else:
                    rsp_data[address] = hex_data
            except Exception as err:
                self.logger.debug("Can't get mem data with dump data %s! Because of:\r\n %s" % (data, err))

        if len(rsp_data) > 0:
            return rsp_data
        else:
            return None

    @staticmethod
    def prepare_memory_dump_command(start_address, length):
        """

        :param start_address: Memory address to read.
        :param length: Memory read length.
        :return: memory dump command
        """
        command = 'mem -dump %s %s' % (hex(start_address), hex(length))
        return command

    def memory_dump_data_parser(self, dump_data):
        """

        :param dump_data:
        :return:
        """
        rsp_data_list = {}
        rsp_data = dump_data.replace(self.serial_until, '')
        # TODO: some case it's happen
        rsp_data = rsp_data.replace(' #', '')
        rsp_data.strip()
        rsp_data = rsp_data.strip()
        self.logger.debug('after clean up rsp_data:%s' % rsp_data)
        data_list = rsp_data.split('\r\n')
        self.logger.debug("data_list: %s" % data_list)
        # check address offset
        for data in data_list:
            try:
                self.logger.debug('data: %s' % data)
                address = int(data[:8], 16)
                self.logger.debug("address: %s" % hex(address))
                hex_data = data[11:60]
                hex_data = hex_data.replace(' ', '')
                hex_data = hex_data.replace('-', '')
                self.logger.debug("hex_data: %s" % hex_data)
                if len(hex_data) != 32:
                    self.logger.error('hex_data length format error!')
                else:
                    rsp_data_list[address] = hex_data
            except Exception as err:
                self.logger.debug("Can't get mem data with dump data %s! Because of:\r\n %s" % (data, err))

        if len(rsp_data_list) > 0:
            return rsp_data_list
        else:
            return None

    def _dump_memroy(self, start_address, size):
        ''' Using memory read command to dump memory data dict.

        :param start_address: Memory address to read.
        :param size: Memory read size.
        :return: Memory data dict.
        '''
        self.serial.recvrepeat(timeout=0.1)
        self.logger.debug("Trying to get %s bytes mem data from %s" % (hex(size), hex(start_address)))
        command = self.prepare_memory_dump_command(start_address, size)

        rsp_data = self.send_and_recvuntil(command, timeout=3)
        rsp_data = rsp_data.replace(command + '\r\n', '')
        mem_data_list = self.memory_dump_data_parser(rsp_data)
        if not mem_data_list:
            return None
        self.logger.debug("length of mem_data_list is %s, correct length is %s" % (hex(len(mem_data_list)), hex((size / 0x10))))
        if len(mem_data_list) < (size / 0x10) - 0x10:
            return None
        return mem_data_list

    def get_mem_dump(self, start_address, size, interval=0x1000):
        '''Get memory data from target

        :param start_address: Memory address to read.
        :param size: Total memory read size.
        :param interval: Memory size per read.
        :return: Memory data
        '''
        mem_dump_data_dict = {}
        mem_dump_data = ''
        # Add panding header for 16 bytes align.
        padding_start_length = 0
        if start_address % 0x10 != 0:
            self.logger.debug("Dump address %s is not 16 bytes aligned" % hex(start_address))
            padding_start_length = start_address % 0x10
        self.logger.debug("Add padding %s bytes to start" % hex(padding_start_length))
        # Add panding for 16 bytes align.
        current_length = size + padding_start_length
        if current_length % 0x10 != 0:
            current_length += 0x10 - (current_length % 0x10)
        if current_length < interval:
            interval = current_length
        for address in range(start_address - padding_start_length,
                             start_address + current_length - padding_start_length,
                             interval):
            mem_data_list = self._dump_memroy(address, interval)
            while not mem_data_list:
                mem_data_list = self._dump_memroy(address, interval)
            self.logger.debug('mem_data_list: %s' % mem_data_list)
            if len(mem_data_list):
                # fix data
                for offset in range(address, address + interval, 0x10):
                    if offset not in mem_data_list:
                        self.logger.debug("Can't Find %s in return mem data list, trying to read data again" % hex(address))
                        temp_data = self._dump_memroy(offset, 0x10)
                        while not temp_data:
                            temp_data = self._dump_memroy(offset, 0x10)
                        mem_data_list[offset] = temp_data[offset]
            else:
                self.logger.warn("Can't get mem_data from: %s with interval: %s" % (hex(address), hex(interval)))
            mem_dump_data_dict.update(mem_data_list)
        # get raw_dump
        for address in range(start_address - padding_start_length, start_address + size, 0x10):
            mem_dump_data += mem_dump_data_dict[address].decode('hex')
        return mem_dump_data[padding_start_length:size + padding_start_length]

    def write_memory_data(self, address, data, check=True):
        """

        :param address: Memory address to write data.
        :param data: Data to write
        :param check: True, check write result, False write to memory without check.
        :return:
        """
        write_length = len(data)
        for offset in range(0, write_length, 0x04):
            current_write_address = address + offset
            write_data = data[offset:offset + 4].encode("hex")
            self._write_single_memory_data(current_write_address, write_data)
        current_data = self.get_mem_dump(address, write_length)
        # TODO: Need improve, should only write missed data.
        if check:
            if (data == current_data) is False:
                self.write_memory_data(address, data)

    def _write_single_memory_data(self, address, data):
        """Write 4 bytes of memory data.

        :param address:
        :param data:
        :return:
        """
        command = "mem -md %s %s" % (hex(address), data)
        self.send_and_recvuntil(command)

    def not_implemented(self, func_name):
        '''
        log access to unimplemented method and raise error

        :param func_name: name of unimplemented function.
        :raise: NotImplementedError detailing the function the is not implemented.
        '''
        msg = '%s is not overridden by %s' % (func_name, type(self).__name__)
        self.logger.error(msg)
        raise NotImplementedError(msg)