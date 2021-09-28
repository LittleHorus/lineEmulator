from time import strftime
import numpy as np
import struct


class Packet(object):
    def _init_(self, src_id: int = 0x11, dst_id: int = 0x12, data_type: int = 0x01):
        self.data = list()
        self.reg_number = 0x0001
        self._line_addr = 0x10
        self._src_addr = 0x01 | self._line_addr
        self._dst_addr = 0x02 | self._line_addr
        self.cmd = 0x01
        self.data_type = 0x01
        self.data_mode = 'Fixed'
        self.string_to_log = str()
        self.fixed_packet = [0x02, 0x01, 0x11, 0x00, 0x01, 0x01]
        self.data_length = 6

    @property
    def src_addr(self):
        return self._src_addr

    @src_addr.setter
    def src_addr(self, value):
        self._src_addr = self._line_addr | (value & 0x0f)

    @property
    def dst_addr(self):
        return self._dst_addr

    @dst_addr.setter
    def dst_addr(self, value):
        self._dst_addr = self._line_addr | (value & 0x0f)

    @property
    def line_addr(self):
        return self._line_addr

    @line_addr.setter
    def line_addr(self, value):
        self._line_addr = value

    def data_packet_in(self, data_to_send):
        self.fixed_packet = [0x02, 0x01, 0x11, 0x00, 0x01, 0x01]

    @staticmethod
    def data_put(data_type, data: list, value) -> list:
        if data_type == 0x02:
            data[5] = (value >> 8) & 0xff
            data[6] = value & 0xff
        elif data_type == 0x03:
            data[5] = (value >> 24) & 0xff
            data[6] = (value >> 16) & 0xff
            data[7] = (value >> 8) & 0xff
            data[8] = value & 0xff
        elif data_type == 0x04:
            ba = bytearray(struct.pack("f", value))
            data[5] = ba[0]
            data[6] = ba[1]
            data[7] = ba[2]
            data[8] = ba[3]
        elif data_type == 0x05:
            for i in range(len(value)):
                data[5+i] = value[i]
        else:
            print('unsupported data type value {}'.format(data_type))
        return data

    def data_packet_out(self, data_to_send) -> list:
        # | our address | server address | cmd | reg hi | reg low | data |
        self.fixed_packet = [self._src_addr, self._dst_addr, (self.cmd << 4) | (self.data_type & 0xf),
                                 (self.reg_number >> 8) & 0xff, self.reg_number & 0xff, 0x00]
        if self.data_type == 0x01:
            if self.data_mode == 'Fixed':
                byte_arr = data_to_send
                self.fixed_packet[5] = byte_arr
                self.string_to_log = "[{}] data(byte): {}".format(strftime("%H:%M:%S"), self.fixed_packet[5])
            elif self.data_mode == 'Random':
                self.fixed_packet[5] = np.random.randint(0, 255)
            elif self.data_mode == 'List':
                self.fixed_packet[5] = np.random.randint(0, 255)
        elif self.data_type == 0x02:
            self.fixed_packet += [0x00]
            if self.data_mode == 'Fixed':
                # byte_arr = data_to_send
                self.data_put(self.data_type, self.fixed_packet, data_to_send)
                # self.fixed_packet[5] = (byte_arr >> 8) & 0xff
                # self.fixed_packet[6] = byte_arr & 0xff
                self.string_to_log = "[{}] hex data(short): {}".format(strftime("%H:%M:%S"), data_to_send)
            elif self.data_mode == 'Random':
                data_rand = np.random.randint(0, 16383)
                self.data_put(self.data_type, self.fixed_packet, data_rand)
                # self.fixed_packet[5] = (data_rand >> 8) & 0xff
                # self.fixed_packet[6] = data_rand & 0xff
            elif self.data_mode == 'List':
                data_rand = np.random.randint(0, 16383)
                self.data_put(self.data_type, self.fixed_packet, data_rand)
                # self.fixed_packet[5] = (data_rand >> 8) & 0xff
                # self.fixed_packet[6] = data_rand & 0xff
        elif self.data_type == 0x03 or self.data_type == 0x04:
            self.fixed_packet += [0x00, 0x00, 0x00]
            if self.data_type == 0x03:
                if self.data_mode == 'Fixed':
                    byte_arr = data_to_send
                    self.string_to_log = "[{}] data(word): {}".format(strftime("%H:%M:%S"), data_to_send)
                    self.data_put(self.data_type, self.fixed_packet, data_to_send)
                    # self.fixed_packet[5] = (byte_arr >> 24) & 0xff
                    # self.fixed_packet[6] = (byte_arr >> 16) & 0xff
                    # self.fixed_packet[7] = (byte_arr >> 8) & 0xff
                    # self.fixed_packet[8] = byte_arr & 0xff
                elif self.data_mode == 'Random':
                    data_rand = np.random.randint(0, (2 ** 31) - 1)
                    self.data_put(self.data_type, self.fixed_packet, data_rand)
                    # self.fixed_packet[5] = (data_rand >> 24) & 0xff
                    # self.fixed_packet[6] = (data_rand >> 16) & 0xff
                    # self.fixed_packet[7] = (data_rand >> 8) & 0xff
                    # self.fixed_packet[8] = (data_rand & 0xff)
                    # self.string_to_log = "[{}] data(word): {:4X}".format(strftime("%H:%M:%S"), data_to_send)
                elif self.data_mode == 'List':
                    data_rand = np.random.randint(0, (2 ** 31) - 1)
                    self.data_put(self.data_type, self.fixed_packet, data_rand)
                    # self.fixed_packet[5] = (data_rand >> 24) & 0xff
                    # self.fixed_packet[6] = (data_rand >> 16) & 0xff
                    # self.fixed_packet[7] = (data_rand >> 8) & 0xff
                    # self.fixed_packet[8] = (data_rand & 0xff)
                    self.string_to_log = "[{}] data(word): {:4X}".format(strftime("%H:%M:%S"), data_to_send)
            if self.data_type == 0x04:
                if self.data_mode == 'Fixed':
                    data_float = data_to_send
                    ba = bytearray(struct.pack("f", data_float))
                    self.fixed_packet[5] = ba[0]
                    self.fixed_packet[6] = ba[1]
                    self.fixed_packet[7] = ba[2]
                    self.fixed_packet[8] = ba[3]
                    self.string_to_log = "[{}] data(float): {:02X}{:02X}{:02X}{:02X}({})".format(
                        strftime("%H:%M:%S"), ba[0], ba[1], ba[2], ba[3], data_to_send)
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
                else:
                    pass
        elif self.data_type == 0x05:
            self.fixed_packet += [0x00]*(self.data_length - 1)
        else:
            print('incorrect data type')
        return self.fixed_packet


