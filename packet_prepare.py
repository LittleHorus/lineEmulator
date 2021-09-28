from time import strftime
import numpy as np
import struct


class Packet:
    def _init_(self):
        self.data = list()
        self.reg_number = 0x0001
        self.src_addr = 0x01
        self.dst_addr = 0x02
        self.line_addr = 0x10
        self.cmd = 0x01
        self.data_type = 0x01
        self.data_mode = 'Fixed'
        self.string_to_log = str()
        self.fixed_packet = [0x02, 0x01, 0x11, 0x00, 0x01, 0x01]

    def packet_create(self, data_to_send):
        if self.data_type == 0x01:
            self.fixed_packet = [0x02, 0x01, 0x11, 0x00, 0x01, 0x01]
            # | our address | server address | cmd | reg hi | reg low | data |
            self.fixed_packet[0] = self.src_addr | self.line_addr
            self.fixed_packet[1] = self.dst_addr
            self.fixed_packet[2] = (self.cmd << 4) | (self.data_type & 0xf)
            self.fixed_packet[3] = (self.reg_number >> 8) & 0xff
            self.fixed_packet[4] = self.reg_number & 0xff
            if self.data_mode == 'Fixed':
                byte_arr = data_to_send
                self.fixed_packet[5] = byte_arr
                self.string_to_log = "[{}] data(byte): {}".format(strftime("%H:%M:%S"), self.fixed_packet[5])
            elif self.data_mode == 'Random':
                self.fixed_packet[5] = np.random.randint(0, 255)
            elif self.data_mode == 'List':
                self.fixed_packet[5] = np.random.randint(0, 255)

        elif self.data_type == 0x02:
            self.fixed_packet = [0x01, 0x02, 0x12, 0x00, 0x01, 0x00, 0x01]
            # | our address | server address | cmd | reg hi | reg low | data |
            self.fixed_packet[0] = self.src_addr | self.line_addr
            self.fixed_packet[1] = self.dst_addr
            self.fixed_packet[2] = (self.cmd << 4) | (self.data_type & 0xf)
            self.fixed_packet[3] = (self.reg_number >> 8) & 0xff
            self.fixed_packet[4] = self.reg_number & 0xff
            if self.data_mode == 'Fixed':
                byte_arr = data_to_send
                self.fixed_packet[5] = (byte_arr >> 8) & 0xff
                self.fixed_packet[6] = byte_arr & 0xff
                self.string_to_log = "[{}] hex data(short): {}".format(strftime("%H:%M:%S"), byte_arr)
            elif self.data_mode == 'Random':
                data_rand = np.random.randint(0, 16383)
                self.fixed_packet[5] = (data_rand >> 8) & 0xff
                self.fixed_packet[6] = data_rand & 0xff
            elif self.data_mode == 'List':
                data_rand = np.random.randint(0, 16383)
                self.fixed_packet[5] = (data_rand >> 8) & 0xff
                self.fixed_packet[6] = data_rand & 0xff

        elif self.data_type == 0x03:
            self.fixed_packet = [0x01, 0x02, 0x13, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01]
            # | our address | server address | cmd | reg hi | reg low | data |
            self.fixed_packet[0] = self.src_addr | self.line_addr
            self.fixed_packet[1] = self.dst_addr
            self.fixed_packet[2] = (self.cmd << 4) | (self.data_type & 0xf)
            self.fixed_packet[3] = (self.reg_number >> 8) & 0xff
            self.fixed_packet[4] = self.reg_number & 0xff
            if self.data_mode == 'Fixed':
                byte_arr = data_to_send
                self.string_to_log = "[{}] data(word): {}".format(strftime("%H:%M:%S"), byte_arr)
                self.fixed_packet[5] = (byte_arr >> 24) & 0xff
                self.fixed_packet[6] = (byte_arr >> 16) & 0xff
                self.fixed_packet[7] = (byte_arr >> 8) & 0xff
                self.fixed_packet[8] = byte_arr & 0xff
            elif self.data_mode == 'Random':
                data_rand = np.random.randint(0, (2**31)-1)
                self.fixed_packet[5] = (data_rand >> 24) & 0xff
                self.fixed_packet[6] = (data_rand >> 16) & 0xff
                self.fixed_packet[7] = (data_rand >> 8) & 0xff
                self.fixed_packet[8] = (data_rand & 0xff)
                self.string_to_log = "[{}] data(word): {:4X}".format(strftime("%H:%M:%S"), data_rand)
            elif self.data_mode == 'List':
                data_rand = np.random.randint(0, (2**31)-1)
                self.fixed_packet[5] = (data_rand >> 24) & 0xff
                self.fixed_packet[6] = (data_rand >> 16) & 0xff
                self.fixed_packet[7] = (data_rand >> 8) & 0xff
                self.fixed_packet[8] = (data_rand & 0xff)
                self.string_to_log = "[{}] data(word): {:4X}".format(strftime("%H:%M:%S"), data_rand)
        elif self.data_type == 0x04:
            self.fixed_packet = [0x01, 0x02, 0x14, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04]
            # | our address | server address | cmd | reg hi | reg low | data |
            self.fixed_packet[0] = self.src_addr | self.line_addr
            self.fixed_packet[1] = self.dst_addr
            self.fixed_packet[2] = (self.cmd << 4) | (self.data_type & 0xf)
            self.fixed_packet[3] = (self.reg_number >> 8) & 0xff
            self.fixed_packet[4] = self.reg_number & 0xff
            if self.data_mode == 'Fixed':
                data_float = data_to_send
                ba = bytearray(struct.pack("f", data_float))
                self.fixed_packet[5] = ba[0]
                self.fixed_packet[6] = ba[1]
                self.fixed_packet[7] = ba[2]
                self.fixed_packet[8] = ba[3]
                self.string_to_log = "[{}] data(float): {:02X}{:02X}{:02X}{:02X}({})".format(
                    strftime("%H:%M:%S"), ba[0], ba[1], ba[2], ba[3], data_float)
            elif self.data_mode == 'Random':
                data_float = np.random.ranf()
                ba = bytearray(struct.pack("f", data_float))
                self.fixed_packet[5] = ba[0]
                self.fixed_packet[6] = ba[1]
                self.fixed_packet[7] = ba[2]
                self.fixed_packet[8] = ba[3]
                self.string_to_log = "[{}] data(float): {:02X}{:02X}{:02X}{:02X}({})".format(
                    strftime("%H:%M:%S"), ba[0], ba[1], ba[2], ba[3], data_float)
            elif self.data_mode == 'List':
                data_float = np.random.ranf()
                ba = bytearray(struct.pack("f", data_float))
                self.fixed_packet[5] = ba[0]
                self.fixed_packet[6] = ba[1]
                self.fixed_packet[7] = ba[2]
                self.fixed_packet[8] = ba[3]
                self.string_to_log = "[{}] data(float): {:02X}{:02X}{:02X}{:02X}({})".format(
                    strftime("%H:%M:%S"), ba[0], ba[1], ba[2], ba[3], data_float)
        if self.data_type == 0x05:
            self.fixed_packet = [0x01, 0x02, 0x01, 0x11, 0x00, 0x01]
            # | our address | server address | cmd | reg hi | reg low | data |
            self.fixed_packet[0] = self.src_addr | self.line_addr
            self.fixed_packet[1] = self.dst_addr
            self.fixed_packet[2] = (self.cmd << 4) | (self.data_type & 0xf)
            self.fixed_packet[3] = (self.reg_number >> 8) & 0xff
            self.fixed_packet[4] = self.reg_number & 0xff
            if self.data_mode == 'Fixed':
                self.fixed_packet[5] = np.random.random_integers(0, 255)
            elif self.data_mode == 'Random':
                self.fixed_packet[5] = np.random.random_integers(0, 255)
            elif self.data_mode == 'List':
                self.fixed_packet[5] = np.random.random_integers(0, 255)
