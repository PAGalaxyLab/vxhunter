from common import BaseTestCase, mock
from serial_debuger.vx_base_target import VxSerialBaseTarget


class VxSerialCmdDebugerTests(BaseTestCase):
    def setUp(self):
        super(VxSerialCmdDebugerTests, self).setUp()
        self.target = VxSerialBaseTarget()
        self.target.serial = mock.Mock()

    def check_serial_alive(self):
        self.target.check_serial_alive = mock.Mock(return_value=True)
        self.assertEqual(self.target.check_serial_alive(), True)

    def test_send_and_recvuntil(self):
        self.target.check_serial_alive = mock.Mock(return_value=True)
        self.target.serial.sendlinethen = mock.Mock(return_value="help # # some output")
        rsp = self.target.send_and_recvuntil("help")
        self.assertEqual(rsp, "help # # some output")

    def test_prepare_memory_dump_command(self):
        command = self.target.prepare_memory_dump_command(1000, 16)
        self.assertEqual(command, 'mem -dump 0x3e8 0x10')
        command = self.target.prepare_memory_dump_command(0x1000, 0x20)
        self.assertEqual(command, 'mem -dump 0x1000 0x20')

    def test_memory_dump_data_parser(self):
        dump_data = "80001000:  3C 08 10 00 40 88 60 00 - 40 80 68 00 00 00 00 40 \t  <...@.`. @.h....@\r\n#"
        output_data = self.target.memory_dump_data_parser(dump_data)
        self.assertEqual(output_data, {2147487744: '3C081000408860004080680000000040'})
        dump_data = "80001000:  3C 08 10 00 40 88 60 00 - 40 80 68 00 00 00 00 40 \t  <...@.`. @.h....@\r\n" \
                    "80001010:  00 00 00 40 00 00 00 40 - 00 00 00 40 00 00 00 40 \t  ...@...@ ...@...@\r\n#"
        output_data = self.target.memory_dump_data_parser(dump_data)
        self.assertEqual(output_data, {2147487744: '3C081000408860004080680000000040',
                                       2147487760: '00000040000000400000004000000040'})
        # print(output_data)

    def test_dump_memroy(self):
        self.target.send_and_recvuntil = mock.Mock(
            return_value=" mem -dump 0x80001000 0x20\r\n"
                         "80001000:  3C 08 10 00 40 88 60 00 - 40 80 68 00 00 00 00 40 \t  <...@.`. @.h....@\r\n"
                         "80001010:  00 00 00 40 00 00 00 40 - 00 00 00 40 00 00 00 40 \t  ...@...@ ...@...@\r\n#")
        output_data = self.target._dump_memroy(start_address=0x80001000, size=0x20)
        self.assertEqual(output_data, {2147487744: '3C081000408860004080680000000040',
                                       2147487760: '00000040000000400000004000000040'})

    def test_get_mem_dump(self):
        self.target.send_and_recvuntil = mock.Mock(
            return_value=" mem -dump 0x80001000 0x20\r\n"
                         "80001000:  3C 08 10 00 40 88 60 00 - 40 80 68 00 00 00 00 40 \t  <...@.`. @.h....@\r\n"
                         "80001010:  00 00 00 40 00 00 00 40 - 00 00 00 40 00 00 00 40 \t  ...@...@ ...@...@\r\n#")
        output_data = self.target.get_mem_dump(start_address=0x80001000, size=0x20)
        self.assertEqual(output_data.encode('hex'), '3c08100040886000408068000000004000000040000000400000004000000040')