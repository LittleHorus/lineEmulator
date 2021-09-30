#!/usr/bin/python3
# -*- coding: utf-8 -*-
import traceback

from PyQt5 import QtCore
import selectors
import socket

sel_client = selectors.DefaultSelector()


class ClientThread(QtCore.QThread):
	status_packet = QtCore.pyqtSignal(str)

	def __init__(self, connect_ip='0.0.0.0', connect_port='0', client_addr='2'):
		QtCore.QThread.__init__(self, None)
		self.__ip = connect_ip
		self.__port = int(connect_port)
		self.connection_status = False
		self.asyn_recv_flag = False
		self.asyn_recv_raw = ''
		self.client_bus_serial_number = int(client_addr)
		self.server_handshake = [0xda, 0xba, 0x01, 0x01]
		self.server_handshake_bytearray = bytearray(self.server_handshake)

		self.out_inner_address = 0x12
		self.running = False
		self.client_handshake = [0x3d, 0xec, 0x01, 0x01]
		self.client_handshake[3] = int(self.client_bus_serial_number)
		self.client_handshake_bytearray = bytearray(self.client_handshake)
		self.client_regs_dict = {'regs': list(), 'value': list(), 'access_mode': list(), 'data_type': list()}

	def run(self):
		self.running = True
		self.asyn_recv_flag = True
		while self.running:
			if self.asyn_recv_flag is True:
				try:
					self.asyn_recv_raw = self.s.recv(100)
				except:
					pass
				if self.asyn_recv_raw:
					print("client received: {}".format(self.asyn_recv_raw))
					data_to_send = self.packet_processing(self.asyn_recv_raw)
					if data_to_send[0] != 0 and data_to_send[1] != 0:
						self.s.sendall(bytearray(data_to_send))
						print(data_to_send)
					self.asyn_recv_raw = ''
			#events = sel.select(timeout=None)
			#for key, mask in events:
			#	service_connection(key, mask)

	def stop(self):
		self.running = False
		#sel_client.unregister(self.s)
		self.s.close()

	def service_connection(self, key, mask):
		sock = key.fileobj
		data = key.data
		if mask & selectors.EVENT_READ:
			recv_data = sock.recv(64)
			if recv_data:
				print('client received', repr(recv_data))
			else:
				print('client closing connection')
				sel_client.unregister(sock)
				sock.close()
		if mask & selectors.EVENT_WRITE:
			if not data.outb:
				pass
			if data.outb:
				print('client sending', repr(data.outb))
				sent = sock.send(data.outb)
				data.outb = data.outb[sent:]

	def connect_client(self, ip, port):
		self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.s.settimeout(1)
		#self.s.setblocking(False)
		self.s.connect((ip, port))

		#self.events = selectors.EVENT_READ | selectors.EVENT_WRITE
		#data = types.SimpleNamespace(inb=b'', outb=b'')
		#sel_client.register(self.s, self.events, data=data)

		self.s.send(self.client_handshake_bytearray)
		data_raw = self.s.recv(64)
		if data_raw[0] == 0xDA and data_raw[1] == 0xBA:
			print('[client] Server handshake: {}'.format(data_raw))
			self.status_packet.emit("HANDSHAKE[server]: " + ''.join('0x{:02X} '.format(a) for a in data_raw))
		else:
			print('client unknown response: {}'.format(data_raw))

	def close_connection(self):
		self.s.close()

	def process_raw(self, raw_data):
		print(raw_data)

	def packet_processing(self, input_data):
		data_response = list()
		# | our address | server address | cmd | reg hi | reg low | data |
		if input_data[0] == 0xda and input_data[1] == 0xba:
			# self.status_signal.emit("byte data type, length: {}".format(len(input_data)))
			self.status_packet.emit("HANDSHAKE[server]: "+''.join('0x{:02X} '.format(a) for a in input_data))
			data_response = [0]*4  # [0x3d, 0xec, 0x01, 0x01]
			data_response[0] = 0x3d
			data_response[1] = 0xec
			data_response[2] = 0x01  # protocol version
			data_response[3] = 0x01  # net address
		elif ((input_data[1]) & 0x0f) == 0x02:
			# self.status_signal.emit("byte data type, length: {}".format(len(input_data)))
			# self.status_packet.emit("RECEIVED: "+''.join('0x{:02X} '.format(a) for a in input_data))
			reg_in_base_bool = False
			element_index = 0
			reg_addr_request = 0
			if ((input_data[2]) & 0xf0) == 0x10:
				reg_addr_request = (input_data[3] << 8) | input_data[4]
				if reg_addr_request in self.client_regs_dict['regs']:
					element_index = self.client_regs_dict['regs'].index(reg_addr_request)
					reg_in_base_bool = True
				else:
					reg_in_base_bool = False
			if ((input_data[2]) & 0xf0) == 0x20:
				reg_addr_request = (input_data[3] << 8) | input_data[4]
				if reg_addr_request in self.client_regs_dict['regs']:
					element_index = self.client_regs_dict['regs'].index(reg_addr_request)
					reg_in_base_bool = True
				else:
					reg_in_base_bool = False

			if (input_data[2] & 0x0f) == 0x01:
				data_response = [0]*6
				data_response[0] = self.out_inner_address
				data_response[1] = input_data[0]
				data_response[2] = (input_data[2] & 0x0f) | 0x60
				for a in range(len(input_data)-3):
					data_response[a+3] = input_data[a+3]
			elif (input_data[2] & 0x0f) == 0x02:
				data_response = [0]*7
				data_response[0] = self.out_inner_address
				data_response[1] = input_data[0]
				data_response[2] = (input_data[2] & 0x0f) | 0x60
				for a in range(len(input_data)-3):
					data_response[a+3] = input_data[a+3]
			elif (input_data[2] & 0x0f) == 0x03:
				data_response = [0]*9
				data_response[0] = self.out_inner_address
				data_response[1] = input_data[0]
				data_response[2] = (input_data[2] & 0x0f) | 0x60
				for a in range(len(input_data)-3):
					data_response[a+3] = input_data[a+3]
			elif (input_data[2] & 0x0f) == 0x04:
				data_response = [0]*9
				data_response[0] = self.out_inner_address
				data_response[1] = input_data[0]
				data_response[2] = (input_data[2] & 0x0f) | 0x60
				for a in range(len(input_data)-3):
					data_response[a+3] = input_data[a+3]

			elif (input_data[2] & 0x0f) == 0x05:
				data_response = [0] * len(input_data)
				data_response[0] = input_data[0]
				data_response[1] = 0x11
				data_response[2] = (input_data[2] & 0x0f) | 0x50
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
						self.client_regs_dict['value'][element_index] = data_bytes
						self.client_regs_dict['data_type'][element_index] = 'byte_array'
					else:
						self.client_regs_dict['regs'].append(reg_addr_request)
						self.client_regs_dict['value'].append(data_bytes)
						self.client_regs_dict['data_type'].append('byte_array')

				if ((input_data[2]) & 0xf0) == 0x20:  # read
					if reg_in_base_bool is True:
						for i in range(packet_data_length):
							data_response[9+i] = self.client_regs_dict['value'][element_index][i]
					else:
						for i in range(packet_data_length):
							data_response[9+i] = 0
			else:
				pass
				#self.status_signal.emit("data type unknown: {}, cmd byte: {}".format((input_data[2]&0x0f), input_data[2]))
		else:
			#print("packet pass{}".format(input_data))
			#self.status_signal.emit("packet pass: {}".format(input_data))
			data_response = [0]*10
		return data_response

	def client_receive_message(self):
		receive_bytearray = ''
		receive_bytearray = self.s.recv(64)
		return receive_bytearray
