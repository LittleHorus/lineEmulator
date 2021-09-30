#!/usr/bin/python3
# -*- coding: utf-8 -*-

from PyQt5 import QtCore
import selectors
import types
import socket
import numpy as np

sel = selectors.DefaultSelector()

__version__ = '0.0.1'
__author__ = 'lha_hl'


class ServerThread(QtCore.QThread):
	status_signal = QtCore.pyqtSignal(str)
	status_packet = QtCore.pyqtSignal(str)
	data = QtCore.pyqtSignal(np.ndarray)
	progress = QtCore.pyqtSignal(int)
	client_connect = QtCore.pyqtSignal(bool)

	def __init__(self, server_ip='', server_port=9110):
		# QtCore.QThread.__init__(self, parent)
		super().__init__()
		self.running = False

		# 'Server IP: {}'.format(socket.gethostbyname(socket.gethostname()))
		self.detected_server_ip = socket.gethostbyname(socket.gethostname())
		self.server_port_inner = server_port
		self.server_ip_inner = server_ip
		self.data_type = 0x01  # 1-byte 2-short 3-word 4-float 5 - dynamic len
		self.command_type = 0x01  # cmd 1-write 2-read 6-response 7 - notification 5 - error read/write
		self.data_len = 0x01  # 1-byte 2-short 4-word/short
		self.data = 0x00
		self.address = 0x12  # client network address
		self.data_send_asyo = ''
		self.server_regs_dict = {'regs': list(), 'value': list(), 'access_mode': list(), 'data_type': list()}
		self.current_packet_dict = {'reg': 0, 'value': 0, 'access_mode': 'rw', 'data_type': 'byte'}
		self.server_transmit_packet_counter = 0
		self.server_received_packet_counter = 0
		self.line_number = 0x01

		# 3 in [1, 2, 3]  # => True
		# ["foo", "bar", "baz"].index("bar")

	def server_send_data(self, data):
		self.data_send_asyo = data

	def run(self):
		self.lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.lsock.bind(('', self.server_port_inner))
		self.lsock.listen()

		self.lsock.setblocking(False)
		sel.register(self.lsock, selectors.EVENT_READ, data=None)

		self.running = True

		while self.running:
			events = sel.select(timeout=None)
			for key, mask in events:
				if key.data is None:
					self.accept_wrapper(key.fileobj)
				else:
					self.service_connection(key, mask)

	def stop(self):
		self.running = False
		sel.unregister(self.lsock)
		self.lsock.close()

	def accept_wrapper(self, sock):
		conn, addr = sock.accept()  # Should be ready to read
		print('server accept connection from', addr)
		self.status_signal.emit("server accept connection from {}".format(addr))
		conn.setblocking(False)
		data = types.SimpleNamespace(addr=addr, inb=b'', outb=b'')
		events = selectors.EVENT_READ | selectors.EVENT_WRITE
		sel.register(conn, events, data=data)

	def service_connection(self, key, mask):
		sock = key.fileobj
		data = key.data
		if mask & selectors.EVENT_READ:
			recv_data = sock.recv(128)  # Should be ready to read
			if recv_data:
				data.outb = recv_data
				print('server recv_data: ' + ''.join('0x{:02X} '.format(a) for a in recv_data))
			else:
				print('server closing connection to', data.addr)
				self.status_signal.emit("server closing connection to {}".format(data.addr))
				sel.unregister(sock)
				sock.close()
				self.client_connect.emit(False)
		if mask & selectors.EVENT_WRITE:
			if data.outb:
				# print('sending: ', repr(data.outb), 'to', data.addr)
				self.status_signal.emit("sending: {}, to {}".format(data.outb, data.addr))

				data_ts = self.packet_processing(data.outb)
				print('server event_write: {}'.format(data_ts))
				if (data_ts[0] == 0) and (data_ts[1] == 0):
					self.status_signal.emit("skip response")
					# todo change for mirror response
					data.outb = b''
				else:
					self.status_signal.emit("sending: {}".format(repr(data.outb), data.addr))
					self.status_packet.emit("SEND         : " + ''.join('0x{:02X} '.format(a) for a in data_ts))
					sent = sock.send(bytearray(data_ts))  # Should be ready to write
					self.server_transmit_packet_counter += 1
					data.outb = b''
			else:
				if self.data_send_asyo:
					print("server asyo send data: {}".format(self.data_send_asyo))
					sent = sock.send(self.data_send_asyo)
					self.data_send_asyo = ''
					self.server_transmit_packet_counter += 1

	def packet_processing(self, input_data):
		data_response = list()
		self.server_received_packet_counter += 1
		# | our address | server address | cmd | reg hi | reg low | data |
		if input_data[0] == 0x3d and input_data[1] == 0xec:
			self.status_signal.emit("byte data type, length: {}".format(len(input_data)))
			self.client_connect.emit(True)
			self.status_packet.emit("HANDSHAKE[client]: " + ''.join('0x{:02X} '.format(a) for a in input_data))
			print('server recv handshake: {}'.format(input_data))
			data_response = [0xDA, 0xBA, 0x01, 0x01]
			print('server send handshake: {}'.format(data_response))

		elif ((input_data[1]) & 0x0f) == 0x01 and (
				((input_data[2]) & 0xf0) == 0x10 or ((input_data[2]) & 0xf0) == 0x20):
			# print("byte data type, length: {}".format(len(input_data)))
			self.status_signal.emit("byte data type, length: {}".format(len(input_data)))
			self.status_packet.emit("RECEIVED: " + ''.join('0x{:02X} '.format(a) for a in input_data))
			reg_in_base_bool = False
			element_index = 0
			reg_addr_request = 0
			if ((input_data[2]) & 0xf0) == 0x10:
				reg_addr_request = (input_data[3] << 8) | input_data[4]
				if reg_addr_request in self.server_regs_dict['regs']:
					element_index = self.server_regs_dict['regs'].index(reg_addr_request)
					reg_in_base_bool = True
				else:
					reg_in_base_bool = False
			if ((input_data[2]) & 0xf0) == 0x20:
				reg_addr_request = (input_data[3] << 8) | input_data[4]
				if reg_addr_request in self.server_regs_dict['regs']:
					element_index = self.server_regs_dict['regs'].index(reg_addr_request)
					reg_in_base_bool = True
				else:
					reg_in_base_bool = False

			if (input_data[2] & 0x0f) == 0x01:
				data_response = [0] * 6
				data_response[0] = input_data[0]
				data_response[1] = 0x11
				data_response[2] = (input_data[2] & 0x0f) | 0x60
				data_response[3] = input_data[3]  # reg hi
				data_response[4] = input_data[4]  # reg lo

				if ((input_data[2]) & 0xf0) == 0x10:  # write
					data_response[5] = input_data[5]
					if reg_in_base_bool is True:
						self.server_regs_dict['value'][element_index] = input_data[5]
					else:
						self.server_regs_dict['regs'].append(reg_addr_request)
						self.server_regs_dict['value'].append(input_data[5])
						self.server_regs_dict['data_type'].append('byte')
				if ((input_data[2]) & 0xf0) == 0x20:  # read
					data_response[5] = input_data[5]
					if reg_in_base_bool is True:
						data_response[5] = self.server_regs_dict['value'][element_index]
					else:
						data_response[5] = 0

			elif (input_data[2] & 0x0f) == 0x02:
				data_response = [0] * 7
				data_response[0] = input_data[0]
				data_response[1] = 0x11
				data_response[2] = (input_data[2] & 0x0f) | 0x60
				data_response[3] = input_data[3]  # reg hi
				data_response[4] = input_data[4]  # reg lo

				if ((input_data[2]) & 0xf0) == 0x10:  # write
					if reg_in_base_bool is True:
						self.server_regs_dict['value'][element_index] = (input_data[5] << 8) | input_data[6]
					else:
						self.server_regs_dict['regs'].append(reg_addr_request)
						self.server_regs_dict['value'].append((input_data[5] << 8) | input_data[6])
						self.server_regs_dict['data_type'].append('short')
					for a in range(len(input_data) - 3):
						data_response[a + 3] = input_data[a + 3]
				if ((input_data[2]) & 0xf0) == 0x20:  # read
					if reg_in_base_bool is True:
						data_response[5] = (self.server_regs_dict['value'][element_index] >> 8) & 0xff
						data_response[6] = self.server_regs_dict['value'][element_index] & 0xff
					else:
						data_response[5] = 0
						data_response[6] = 0

			elif (input_data[2] & 0x0f) == 0x03:  # word data type
				data_response = [0] * 9
				data_response[0] = input_data[0]
				data_response[1] = 0x11
				data_response[2] = (input_data[2] & 0x0f) | 0x60
				data_response[3] = input_data[3]  # reg hi
				data_response[4] = input_data[4]  # reg lo

				if ((input_data[2]) & 0xf0) == 0x10:  # write
					if reg_in_base_bool is True:
						self.server_regs_dict['value'][element_index] = \
							(input_data[5] << 24) | (input_data[6] << 16) | (input_data[7] << 8) | input_data[8]
					else:
						self.server_regs_dict['regs'].append(reg_addr_request)
						self.server_regs_dict['value'].append(
							(input_data[5] << 24) | (input_data[6] << 16) | (input_data[7] << 8) | input_data[8])
						self.server_regs_dict['data_type'].append('word')
					for a in range(len(input_data) - 3):
						data_response[a + 3] = input_data[a + 3]
				if ((input_data[2]) & 0xf0) == 0x20:  # read
					if reg_in_base_bool is True:
						data_response[5] = (self.server_regs_dict['value'][element_index] >> 24) & 0xff
						data_response[6] = (self.server_regs_dict['value'][element_index] >> 16) & 0xff
						data_response[7] = (self.server_regs_dict['value'][element_index] >> 8) & 0xff
						data_response[8] = self.server_regs_dict['value'][element_index] & 0xff
					else:
						data_response[5] = 0
						data_response[6] = 0
						data_response[7] = 0
						data_response[8] = 0

			elif (input_data[2] & 0x0f) == 0x04:  # float data type
				data_response = [0] * 9
				data_response[0] = input_data[0]
				data_response[1] = 0x11
				data_response[2] = (input_data[2] & 0x0f) | 0x60
				data_response[3] = input_data[3]  # reg hi
				data_response[4] = input_data[4]  # reg lo

				if ((input_data[2]) & 0xf0) == 0x10:  # write
					if reg_in_base_bool is True:
						self.server_regs_dict['value'][element_index] = \
							(input_data[5] << 24) | (input_data[6] << 16) | (input_data[7] << 8) | input_data[8]
					else:
						self.server_regs_dict['regs'].append(reg_addr_request)
						self.server_regs_dict['value'].append(
							(input_data[5] << 24) | (input_data[6] << 16) | (input_data[7] << 8) | input_data[8])
						self.server_regs_dict['data_type'].append('float')
					for a in range(len(input_data) - 3):
						data_response[a + 3] = input_data[a + 3]
				if ((input_data[2]) & 0xf0) == 0x20:  # read
					if reg_in_base_bool is True:
						data_response[5] = (self.server_regs_dict['value'][element_index] >> 24) & 0xff
						data_response[6] = (self.server_regs_dict['value'][element_index] >> 16) & 0xff
						data_response[7] = (self.server_regs_dict['value'][element_index] >> 8) & 0xff
						data_response[8] = self.server_regs_dict['value'][element_index] & 0xff
					else:
						data_response[5] = 0
						data_response[6] = 0
						data_response[7] = 0
						data_response[8] = 0

			elif (input_data[2] & 0x0f) == 0x05:
				data_response = [0] * len(input_data)
				data_response[0] = input_data[0]
				data_response[1] = 0x11
				data_response[2] = (input_data[2] & 0x0f) | 0x60
				data_response[3] = input_data[3]  # reg hi
				data_response[4] = input_data[4]  # reg lo
				data_response[5] = input_data[5]  # block length
				data_response[6] = input_data[6]  # block length
				data_response[7] = input_data[7]  # block length
				data_response[8] = input_data[8]  # block length
				packet_data_length = \
					(input_data[5] << 24) | (input_data[6] << 16) | (input_data[7] << 8) | input_data[8]

				data_bytes = list()

				if ((input_data[2]) & 0xf0) == 0x10:  # write
					for i in range(packet_data_length):
						data_bytes.append(input_data[9 + i])
					if reg_in_base_bool is True:
						self.server_regs_dict['value'][element_index] = data_bytes
						self.server_regs_dict['data_type'][element_index] = 'byte_array'
					else:
						self.server_regs_dict['regs'].append(reg_addr_request)
						self.server_regs_dict['value'].append(data_bytes)
						self.server_regs_dict['data_type'].append('byte_array')

				if ((input_data[2]) & 0xf0) == 0x20:  # read
					if reg_in_base_bool is True:
						if packet_data_length != (len(self.server_regs_dict['value'][element_index])+9):
							data_response = [0] * (len(self.server_regs_dict['value'][element_index])+9)
							data_response[0] = input_data[0]
							data_response[1] = 0x11
							data_response[2] = (input_data[2] & 0x0f) | 0x60
							data_response[3] = input_data[3]  # reg hi
							data_response[4] = input_data[4]  # reg lo
							data_response[5] = input_data[5]  # block length
							data_response[6] = input_data[6]  # block length
							data_response[7] = input_data[7]  # block length
							data_response[8] = input_data[8]  # block length
						for i in range(len(self.server_regs_dict['value'][element_index])):
							data_response[9+i] = self.server_regs_dict['value'][element_index][i]
					else:
						for i in range(packet_data_length):
							data_response[9+i] = 0
			else:
				self.status_signal.emit(
					"data type unknown: {}, cmd byte: {}".format((input_data[2] & 0x0f), input_data[2]))
				print('server data type unknown: {:2X}'.format(input_data))
		else:
			print("packet pass{}".format(input_data))
			self.status_signal.emit("packet pass: {}".format(input_data))
			data_response = [0] * 10
		return data_response

