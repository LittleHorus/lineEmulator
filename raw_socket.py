#!/usr/bin/python3
# -*- coding: utf-8 -*-

import socket
import traceback


class RawSocket:
	#https://docs.python.org/3/library/socket.html
	def __init__(self, socket_type='Server', client_bus_serialnumber=0x02):
		self.__socket_type = socket_type
		self.HOST = '192.168.0.150'
		self.PORT = 9110
		self.SERVER_HOST = socket.gethostbyname(socket.gethostname())
		self.HOST = socket.gethostbyname(socket.gethostname())

		self.server_handshake = [0xda, 0xba, 0x01, 0x01]
		self.server_handshake_bytearray = bytearray(self.server_handshake)

		self.client_handshake = [0x3d,0xec, 0x01, 0x01]
		self.client_handshake[3] = client_bus_serialnumber
		self.client_handshake_bytearray = bytearray(self.client_handshake)

		self.fixed_packet = [0x00]*13
		self.flexible_packet = []
		self.read_packet = []
		self.data_type = 0x01
		self.cmd = 'read'
		self.packet_type = 'fixed'

		self.transaction_number = 0
		self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	def send_fixed_size_packet(self):
		#print("[date][cmd]send fixed size packet: ")

		if self.packet_type == 'fixed':
			if self.cmd == 'write': #0x1x
				self.fixed_packet[6] = (self.data_type & 0x0f) | (0x10)
			if self.cmd == 'read': #0x2x
				self.fixed_packet[6] = (self.data_type & 0x0f) | (0x20)
			if self.cmd == 'response_write_read': #06x
				self.fixed_packet[6] = (self.data_type & 0x0f) | (0x60)
			if self.cmd == 'notification_data_change': #0x7x
				self.fixed_packet[6] = (self.data_type & 0x0f) | (0x70)
			if self.cmd == 'fault_read_write_operation': #0x5x
				self.fixed_pacet[6] = (self.data_type & 0x0f) | (0x50)

	def create_server(self):
		try:
			self.s.settimeout(10)  # sec
			self.s.bind((self.SERVER_HOST, self.PORT))
			self.s.listen(1)
			conn, addr = self.s.accept()
			with conn:
				print('Connected by {}'.format(addr))
				while True:
					data_raw = conn.recv(1024)
					if not data_raw: break
					conn.sendall(data_raw)
		except:
			traceback.print_exc()

	def create_client(self, server_ip, server_port):
		self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.s.settimeout(0.1)  # sec
		self.s.setblocking(False)
		self.s.connect((self.HOST, self.PORT))
		self.s.send(self.client_handshake_bytearray)
		data_raw = self.s.recv(1024)
		if data_raw[0] == 0xDA and data_raw[1] == 0xBA:
			print('Server handshake: {}'.format(data_raw))
		else:
			print('unknown response: {}'.format(data_raw))

	def client_close_connection(self):
		try:
			self.s.close()
		except:
			traceback.print_exc()

	def client_receive_message(self):
		receive_bytearray = ''
		receive_bytearray = self.s.recv(1024)
		return receive_bytearray

	def server_scan_all(self):
		self.s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
		print(self.s.recvfrom(65565))
		self.s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

