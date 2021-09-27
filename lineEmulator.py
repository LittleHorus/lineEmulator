#!/usr/bin/python3
# -*- coding: utf-8 -*-

from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtWidgets import QFileDialog, QWhatsThis
from PyQt5.QtWidgets import QMessageBox
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QCompleter
from PyQt5.QtGui import QRegExpValidator
from PyQt5.QtCore import QTimer

import numpy as np
import os
from time import gmtime, strftime
import time
import traceback
import socket
import sys
import qdarkstyle 
import array
import struct
import binascii
import threading
import selectors
import types

from device_settings_from_xml import XmlDataLoader

sel = selectors.DefaultSelector()
sel_client = selectors.DefaultSelector()

__version__ = '1.0.3'

mark_line = 0x10


class CommonWindow(QtWidgets.QWidget):
	"""Класс основного окна программы"""
	def __init__(self, parent = None):
		QtWidgets.QMainWindow.__init__(self, parent)

		self.data_array = [0]*13
		self.data_bytearray = bytearray(self.data_array)

		vertical_size = 30
		horizontal_size = 80

		self.client_cmd = 0x01
		self.client_data_type = 0x01 
		self.data_in_asyo = ''

		self.server_cmd = 0x01
		self.server_data_type = 0x01

		self.server_state = 0
		
		self.onlyInt = QtGui.QIntValidator(1, 5000)

		self.log_widget = QtWidgets.QPlainTextEdit()
		self.log_widget.insertPlainText("Log: ")
		self.log_widget.setReadOnly(True)				

		self.socket_log_widget = QtWidgets.QPlainTextEdit()
		self.socket_log_widget.insertPlainText("Socket log: ")
		self.socket_log_widget.setReadOnly(True)	

		self.tab_wdg = tabWidgetCustom(self, horizontal_size, vertical_size)

		self.hbox_level1 = QtWidgets.QHBoxLayout()
		self.hbox_level1.addWidget(self.tab_wdg, 0)
		self.hbox_level1.addWidget(self.socket_log_widget, 1)

		self.vbox = QtWidgets.QVBoxLayout()		
		self.vbox.insertLayout(0, self.hbox_level1)
		self.vbox.addWidget(self.log_widget, 1)
		self.setLayout(self.vbox)

		self.tab_wdg.btn_run_server.clicked.connect(self.server_init)
		self.tab_wdg.btn_connect_to_server.clicked.connect(self.on_create_client)

		self.serv_nonblocking = ServerThread(server_ip='192.168.0.150', server_port=9110)
		self.log_widget.appendPlainText("Server IP: {}".format(self.serv_nonblocking.detected_server_ip))
		
		#self.serv_nonblocking.start()

		self.host_ip = ''  # self.serv_nonblocking.detected_server_ip
		# self.tab_wdg.le_addr_tab1.setText("{}".format(self.host_ip))
		
		# self.client = rawSocket("Client")
		self.client = ClientThread(self.tab_wdg.le_addr_tab2.text(), self.tab_wdg.le_port_tab2.text(), self.tab_wdg.le_inner_addr_tab2.text())
		self.client.out_inner_address = int(self.tab_wdg.le_inner_addr_tab2.text(), 16)

		self.tab_wdg.btn_send_data_tab2.clicked.connect(self.on_send_client_mode)
		self.tab_wdg.btn_send_data_tab1.clicked.connect(self.server_send_datapacket)

		self.tab_wdg.cmd_combobox.currentIndexChanged.connect(self.on_client_change_cmd)
		self.tab_wdg.datatype_combobox.currentIndexChanged.connect(self.on_client_change_data_type)
		self.tab_wdg.cmd_combobox_tab1.currentIndexChanged.connect(self.on_server_change_cmd)
		self.tab_wdg.datatype_combobox_tab1.currentIndexChanged.connect(self.on_server_change_data_type)

		self.tab_wdg.le_inner_addr_tab2.textChanged.connect(self.on_update_inner_address)

		# self.tab_wdg.tab1.setDisabled(True)
		self.tab_wdg.tabs.setCurrentIndex(1)

		self.timer = QTimer()
		self.timer.timeout.connect(self.on_timer_interrupt)

		self.timer_client = QTimer()
		self.timer_client.timeout.connect(self.on_timer_client_interrupt)

		# xmlData = XmlDataLoader()
		# xmlData.xml_load("E:\\PythonScripts\\markConnection\\data\\plc_device.xml")

	@QtCore.pyqtSlot()
	def on_timer_interrupt(self):
		# self.log_widget.appendPlainText("[{}] multi shot, repeat time: {} sec".format(strftime("%H:%M:%S"), int(self.tab_wdg.le_timeout_tab2.text())))
		if int(self.tab_wdg.le_timeout_tab2.text()) == 0:
			self.timer.stop()
			self.log_widget.appendPlainText("[{}] timer stopped".format(strftime("%H:%M:%S")))
		else:
			self.on_send_client_mode()	
	
	@QtCore.pyqtSlot()
	def on_timer_client_interrupt(self):
		try:
			self.data_in_asyo = self.client.client_reseive_message()
			if self.data_in_asyo:
				self.log_widget.appendPlainText("[{}] incoming data: {}".format(strftime("%H:%M:%S"), self.data_in_asyo))
		except:
			traceback.print_exc()
	
	@QtCore.pyqtSlot()
	def on_update_inner_address(self):
		tmp_str = self.tab_wdg.le_inner_addr_tab2.text()
		self.client.out_inner_address = int(self.tab_wdg.le_inner_addr_tab2.text(), 16)

	@QtCore.pyqtSlot()
	def on_create_client(self):
		try:
			if self.tab_wdg.btn_connect_to_server.text() == 'Disconnect':
				self.client.close_connection() 
				self.tab_wdg.btn_connect_to_server.setText("Connect")
				self.tab_wdg.led_client_status.toggle()
				self.tab_wdg.le_addr_tab2.setReadOnly(False)
				self.tab_wdg.le_port_tab2.setReadOnly(False)
				self.tab_wdg.btn_send_data_tab2.setDisabled(True)	
				self.log_widget.appendPlainText("[{}] disconnect from server".format(strftime("%H:%M:%S")))
				self.timer.stop()	
				self.client.stop()	
			else:
				ip = self.tab_wdg.le_addr_tab2.text()
				port = int(self.tab_wdg.le_port_tab2.text())
				self.log_widget.appendPlainText("[{}] ip: {} port: {}".format(strftime("%H:%M:%S"), ip, port))
				self.client.connect_client(ip, port)  # ('192.168.0.2', 9110)
				self.tab_wdg.btn_connect_to_server.setText("Disconnect")
				self.tab_wdg.led_client_status.toggle()
				self.tab_wdg.le_addr_tab2.setReadOnly(True)
				self.tab_wdg.le_port_tab2.setReadOnly(True)	
				self.tab_wdg.btn_send_data_tab2.setDisabled(False)	
				self.client.start()	
		except:
			self.tab_wdg.le_addr_tab2.setReadOnly(False)
			self.tab_wdg.le_port_tab2.setReadOnly(False)
			self.tab_wdg.le_inner_addr_tab2.setReadOnly(False)		
			self.log_widget.appendPlainText("[{}] connection failed: {}".format(strftime("%H:%M:%S"),traceback.format_exc()))		
	
	def on_send_client_mode(self):
		try:
			reg_number = int(self.tab_wdg.le_reg_number_tab2.text(), 16)
			cl_addr = int(self.tab_wdg.le_inner_addr_tab2.text(), 16)
			if self.client_data_type == 0x01:
				self.fixed_packet = [0x01, 0x02, 0x11, 0x00, 0x01, 0x01]  # | our address | server address | cmd | reg hi | reg low | data |
				self.fixed_packet[0] = cl_addr 
				self.fixed_packet[1] = 0x01
				self.fixed_packet[2] = (self.client_cmd << 4) | (self.client_data_type & 0xf)
				self.fixed_packet[3] = (reg_number >> 8) & 0xff
				self.fixed_packet[4] = reg_number & 0xff
				if self.tab_wdg.datamode_combobox.currentText() == 'Fixed':
					byte_arr = int(self.tab_wdg.le_data_tab2.text(), 16)
					self.fixed_packet[5] = byte_arr  # int(self.tab_wdg.le_data_tab2.text())
					self.log_widget.appendPlainText("[{}] data(byte): {}".format(strftime("%H:%M:%S"), self.fixed_packet[5]))
				elif self.tab_wdg.datamode_combobox.currentText() == 'Random':
					self.fixed_packet[5] = np.random.randint(0, 255)
				elif self.tab_wdg.datamode_combobox.currentText() == 'List':
					self.fixed_packet[5] = np.random.randint(0, 255)

			elif self.client_data_type == 0x02:
				self.fixed_packet = [0x01, 0x02, 0x12, 0x00, 0x01, 0x00, 0x01]  # | our address | server address | cmd | reg hi | reg low | data |
				self.fixed_packet[0] = cl_addr
				self.fixed_packet[1] = 0x01
				self.fixed_packet[2] = (self.client_cmd << 4) | (self.client_data_type & 0xf)
				self.fixed_packet[3] = (reg_number >> 8) & 0xff
				self.fixed_packet[4] = reg_number & 0xff
				if self.tab_wdg.datamode_combobox.currentText() == 'Fixed':
					byte_arr = int(self.tab_wdg.le_data_tab2.text(), 16)
					self.fixed_packet[5] = (byte_arr >> 8) & 0xff
					self.fixed_packet[6] = byte_arr & 0xff
					self.log_widget.appendPlainText("[{}] hex data(short): {}".format(strftime("%H:%M:%S"), byte_arr))
				elif self.tab_wdg.datamode_combobox.currentText() == 'Random':
					data_rand = np.random.randint(0, 16383)
					self.fixed_packet[5] = (data_rand >> 8) & 0xff
					self.fixed_packet[6] = (data_rand & 0xff)
				elif self.tab_wdg.datamode_combobox.currentText() == 'List':
					data_rand = np.random.randint(0, 16383)
					self.fixed_packet[5] = (data_rand >> 8) & 0xff
					self.fixed_packet[6] = (data_rand & 0xff)

			elif self.client_data_type == 0x03:
				self.fixed_packet = [0x01,0x02,0x13,0x00,0x01,0x00, 0x00, 0x00, 0x01]  # | our address | server address | cmd | reg hi | reg low | data |
				self.fixed_packet[0] = cl_addr 
				self.fixed_packet[1] = 0x01
				self.fixed_packet[2] = (self.client_cmd << 4) | (self.client_data_type & 0xf)
				self.fixed_packet[3] = (reg_number>>8)&0xff
				self.fixed_packet[4] = reg_number&0xff
				if self.tab_wdg.datamode_combobox.currentText() == 'Fixed':
					# data_fixed = int(self.tab_wdg.le_data_tab2.text())
					byte_arr = int(self.tab_wdg.le_data_tab2.text(), 16)
					self.log_widget.appendPlainText("[{}] data(word): {}".format(strftime("%H:%M:%S"), byte_arr))
					self.fixed_packet[5] = (byte_arr >> 24) & 0xff
					self.fixed_packet[6] = (byte_arr >> 16) & 0xff
					self.fixed_packet[7] = (byte_arr >> 8) & 0xff
					self.fixed_packet[8] = (byte_arr & 0xff)
				elif self.tab_wdg.datamode_combobox.currentText() == 'Random':
					data_rand = np.random.randint(0, (2**31)-1)
					self.fixed_packet[5] = (data_rand >> 24) & 0xff
					self.fixed_packet[6] = (data_rand >> 16) & 0xff
					self.fixed_packet[7] = (data_rand >> 8) & 0xff
					self.fixed_packet[8] = (data_rand & 0xff)
					self.log_widget.appendPlainText("[{}] data(word): {:4X}".format(strftime("%H:%M:%S"), data_rand))
				elif self.tab_wdg.datamode_combobox.currentText() == 'List':
					data_rand = np.random.randint(0, (2**31)-1)
					self.fixed_packet[5] = (data_rand >> 24) & 0xff
					self.fixed_packet[6] = (data_rand >> 16) & 0xff
					self.fixed_packet[7] = (data_rand >> 8) & 0xff
					self.fixed_packet[8] = (data_rand & 0xff)
					self.log_widget.appendPlainText("[{}] data(word): {:4X}".format(strftime("%H:%M:%S"), data_rand))

			elif self.client_data_type == 0x04:
				self.fixed_packet = [0x01, 0x02, 0x14, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04]  # | our address | server address | cmd | reg hi | reg low | data |
				self.fixed_packet[0] = cl_addr
				self.fixed_packet[1] = 0x01
				self.fixed_packet[2] = (self.client_cmd << 4) | (self.client_data_type & 0xf)
				self.fixed_packet[3] = (reg_number >> 8) & 0xff
				self.fixed_packet[4] = reg_number & 0xff
				if self.tab_wdg.datamode_combobox.currentText() == 'Fixed':
					data_float = float(self.tab_wdg.le_data_tab2.text())
					ba = bytearray(struct.pack("f", data_float)) 
					self.fixed_packet[5] = ba[0]
					self.fixed_packet[6] = ba[1]
					self.fixed_packet[7] = ba[2]
					self.fixed_packet[8] = ba[3]
					self.log_widget.appendPlainText("[{}] data(float): {:02X}{:02X}{:02X}{:02X}({})"
													.format(strftime("%H:%M:%S"), ba[0], ba[1], ba[2], ba[3], data_float))
				elif self.tab_wdg.datamode_combobox.currentText() == 'Random':
					data_float = np.random.ranf()
					ba = bytearray(struct.pack("f", data_float)) 
					self.fixed_packet[5] = ba[0]
					self.fixed_packet[6] = ba[1]
					self.fixed_packet[7] = ba[2]
					self.fixed_packet[8] = ba[3]
					self.log_widget.appendPlainText("[{}] data(float): {:02X}{:02X}{:02X}{:02X}({})"
													.format(strftime("%H:%M:%S"), ba[0], ba[1], ba[2], ba[3], data_float))
				elif self.tab_wdg.datamode_combobox.currentText() == 'List':
					data_float = np.random.ranf()
					ba = bytearray(struct.pack("f", data_float)) 
					self.fixed_packet[5] = ba[0]
					self.fixed_packet[6] = ba[1]
					self.fixed_packet[7] = ba[2]
					self.fixed_packet[8] = ba[3]
					self.log_widget.appendPlainText("[{}] data(float): {:02X}{:02X}{:02X}{:02X}({})"
													.format(strftime("%H:%M:%S"), ba[0],ba[1],ba[2],ba[3], data_float))

			if self.client_data_type == 0x05:
				self.fixed_packet = [0x01, 0x02, 0x01, 0x11, 0x00, 0x01]  # | our address | server address | cmd | reg hi | reg low | data |
				self.fixed_packet[0] = cl_addr
				self.fixed_packet[1] = 0x01
				self.fixed_packet[2] = (self.client_cmd << 4)|(self.client_data_type & 0xf)
				self.fixed_packet[3] = (reg_number >> 8) & 0xff
				self.fixed_packet[4] = reg_number & 0xff
				if self.tab_wdg.datamode_combobox.currentText() == 'Fixed':
					self.fixed_packet[5] = int(self.tab_wdg.le_data_tab2.text())
				elif self.tab_wdg.datamode_combobox.currentText() == 'Random':
					self.fixed_packet[5] = np.random.random_integers(0, 255)
				elif self.tab_wdg.datamode_combobox.currentText() == 'List':
					self.fixed_packet[5] = np.random.random_integers(0, 255)

			if int(self.tab_wdg.le_timeout_tab2.text()) != 0:
				self.timer.start(int(self.tab_wdg.le_timeout_tab2.text())*1000)
				self.log_widget.appendPlainText("[{}] multi shot, repeat time: {} sec".format(strftime("%H:%M:%S"), int(self.tab_wdg.le_timeout_tab2.text())))
			else:
				self.timer.stop()
				self.log_widget.appendPlainText("[{}] single shot".format(strftime("%H:%M:%S")))
			self.socket_log_widget.appendPlainText("[{}] SEND: ".format(strftime("%H:%M:%S")) +''.join('0x{:02X} '.format(a) for a in self.fixed_packet))
			self.client.asyn_recv_flag = False
			self.client.s.sendall(bytearray(self.fixed_packet))	
			data_raw = self.client.s.recv(1024)
			self.client.asyn_recv_flag = True
			self.log_widget.appendPlainText("[{}] recv: {}".format(strftime("%H:%M:%S"), data_raw))
			self.socket_log_widget.appendPlainText("[{}] RECV: ".format(strftime("%H:%M:%S")) + ''.join('0x{:02X} '.format(a) for a in data_raw)) 
		except:
			self.client.asyn_recv_flag = True
			self.log_widget.appendPlainText("[{}] RECV: {}".format(strftime("%H:%M:%S"), traceback.format_exc()))
			self.socket_log_widget.appendPlainText("[{}] RECV: TIMEOUT".format(strftime("%H:%M:%S")))
	
	def on_status_to_log(self, status_str):
		self.log_widget.appendPlainText("[{}] {}".format(strftime("%H:%M:%S"), status_str))
	
	def on_status_to_log_socket(self, status_str):
		self.socket_log_widget.appendPlainText("[{}] {}".format(strftime("%H:%M:%S"), status_str))
	
	def on_send_size(self):
		print(self.tab_wdg.tabs.size())
	
	@QtCore.pyqtSlot()
	def on_client_change_cmd(self):
		if self.tab_wdg.cmd_combobox.currentText() == 'Write[0x1x]':
			self.log_widget.appendPlainText("[{}] change cmd[client]: {}".format(strftime("%H:%M:%S"), self.tab_wdg.cmd_combobox.currentText()))
			self.client_cmd = 0x01
		elif self.tab_wdg.cmd_combobox.currentText() == 'Read[0x2x]':
			self.log_widget.appendPlainText("[{}] change cmd[client]: {}".format(strftime("%H:%M:%S"), self.tab_wdg.cmd_combobox.currentText()))
			self.client_cmd = 0x02
		else:
			self.log_widget.appendPlainText("[{}] failed change cmd[client]: {}".format(strftime("%H:%M:%S"), self.tab_wdg.cmd_combobox.currentText()))
	
	@QtCore.pyqtSlot()
	def on_server_change_cmd(self):
		if self.tab_wdg.cmd_combobox_tab1.currentText() == 'Write[0x1x]':
			self.log_widget.appendPlainText("[{}] change cmd[server]: {}".format(strftime("%H:%M:%S"), self.tab_wdg.cmd_combobox_tab1.currentText()))
			self.server_cmd = 0x01
		elif self.tab_wdg.cmd_combobox_tab1.currentText() == 'Read[0x2x]':
			self.log_widget.appendPlainText("[{}] change cmd[server]: {}".format(strftime("%H:%M:%S"), self.tab_wdg.cmd_combobox_tab1.currentText()))
			self.server_cmd = 0x02
		else:
			self.log_widget.appendPlainText("[{}] failed change cmd[server]: {}".format(strftime("%H:%M:%S"), self.tab_wdg.cmd_combobox_tab1.currentText()))
	
	@QtCore.pyqtSlot()
	def on_client_change_data_type(self):
		if self.tab_wdg.datatype_combobox.currentText() == 'Byte[I8/U8]':
			self.log_widget.appendPlainText("[{}] change data type[client]: {}".format(strftime("%H:%M:%S"), self.tab_wdg.datatype_combobox.currentText()))
			self.client_data_type = 0x01
			self.tab_wdg.le_data_tab2.setValidator(QRegExpValidator(QtCore.QRegExp("[a-fA-F0-9]{2}")))
			self.tab_wdg.le_data_tab2.setText("00")			
		elif self.tab_wdg.datatype_combobox.currentText() == 'Short[I16/U16]':
			self.log_widget.appendPlainText("[{}] change data type[client]: {}".format(strftime("%H:%M:%S"), self.tab_wdg.datatype_combobox.currentText()))
			self.client_data_type = 0x02		
			self.tab_wdg.le_data_tab2.setValidator(QRegExpValidator(QtCore.QRegExp("[a-fA-F0-9]{4}")))
			self.tab_wdg.le_data_tab2.setText("0000")
		elif self.tab_wdg.datatype_combobox.currentText() == 'Word[I32/U32]':
			self.log_widget.appendPlainText("[{}] change data type[client]: {}".format(strftime("%H:%M:%S"), self.tab_wdg.datatype_combobox.currentText()))
			self.client_data_type = 0x03	
			self.tab_wdg.le_data_tab2.setValidator(QRegExpValidator(QtCore.QRegExp("[a-fA-F0-9]{8}")))
			self.tab_wdg.le_data_tab2.setText("00000000")			
		elif self.tab_wdg.datatype_combobox.currentText() == 'Real[Float]':
			self.log_widget.appendPlainText("[{}] change data type[client]: {}".format(strftime("%H:%M:%S"), self.tab_wdg.datatype_combobox.currentText()))
			self.client_data_type = 0x04
			self.tab_wdg.le_data_tab2.setValidator(QRegExpValidator(QtCore.QRegExp("-?(0(\.\d*)?|([1-9]\d*\.?\d*)|(\.\d+))([Ee][+-]?\d+)?")))
			self.tab_wdg.le_data_tab2.setText("0.0")					
		elif self.tab_wdg.datatype_combobox.currentText() == 'nByte[Custom]':
			self.log_widget.appendPlainText("[{}] change data type[client]: {}".format(strftime("%H:%M:%S"), self.tab_wdg.datatype_combobox.currentText()))
			self.client_data_type = 0x05
			self.tab_wdg.le_data_tab2.setValidator(QRegExpValidator(QtCore.QRegExp("[a-fA-F0-9]{20}")))
			self.tab_wdg.le_data_tab2.setText("00000000")			
		else:
			self.log_widget.appendPlainText("[{}] failet change datatype[client]: {}".format(strftime("%H:%M:%S"), self.tab_wdg.datatype_combobox.currentText()))			
	
	@QtCore.pyqtSlot()
	def on_server_change_data_type(self):
		if self.tab_wdg.datatype_combobox_tab1.currentText() == 'Byte[I8/U8]':
			self.log_widget.appendPlainText("[{}] change data type[server]: {}".format(strftime("%H:%M:%S"), self.tab_wdg.datatype_combobox_tab1.currentText()))
			self.server_data_type = 0x01
			self.tab_wdg.le_data_tab1.setValidator(QRegExpValidator(QtCore.QRegExp("[a-fA-F0-9]{2}")))
			self.tab_wdg.le_data_tab1.setText("00")			
		elif self.tab_wdg.datatype_combobox_tab1.currentText() == 'Short[I16/U16]':
			self.log_widget.appendPlainText("[{}] change data type[server]: {}".format(strftime("%H:%M:%S"), self.tab_wdg.datatype_combobox_tab1.currentText()))
			self.server_data_type = 0x02		
			self.tab_wdg.le_data_tab1.setValidator(QRegExpValidator(QtCore.QRegExp("[a-fA-F0-9]{4}")))
			self.tab_wdg.le_data_tab1.setText("0000")
		elif self.tab_wdg.datatype_combobox_tab1.currentText() == 'Word[I32/U32]':
			self.log_widget.appendPlainText("[{}] change data type[server]: {}".format(strftime("%H:%M:%S"), self.tab_wdg.datatype_combobox_tab1.currentText()))
			self.server_data_type = 0x03	
			self.tab_wdg.le_data_tab1.setValidator(QRegExpValidator(QtCore.QRegExp("[a-fA-F0-9]{8}")))
			self.tab_wdg.le_data_tab1.setText("00000000")			
		elif self.tab_wdg.datatype_combobox_tab1.currentText() == 'Real[Float]':
			self.log_widget.appendPlainText("[{}] change data type[server]: {}".format(strftime("%H:%M:%S"), self.tab_wdg.datatype_combobox_tab1.currentText()))
			self.server_data_type = 0x04
			self.tab_wdg.le_data_tab1.setValidator(QRegExpValidator(QtCore.QRegExp("-?(0(\.\d*)?|([1-9]\d*\.?\d*)|(\.\d+))([Ee][+-]?\d+)?")))
			self.tab_wdg.le_data_tab1.setText("0.0")					
		elif self.tab_wdg.datatype_combobox_tab1.currentText() == 'nByte[Custom]':
			self.log_widget.appendPlainText("[{}] change data type[server]: {}".format(strftime("%H:%M:%S"), self.tab_wdg.datatype_combobox_tab1.currentText()))
			self.server_data_type = 0x05
			self.tab_wdg.le_data_tab1.setValidator(QRegExpValidator(QtCore.QRegExp("[a-fA-F0-9]{20}")))
			self.tab_wdg.le_data_tab1.setText("00000000")			
		else:
			self.log_widget.appendPlainText("[{}] failet change datatype[server]: {}".format(strftime("%H:%M:%S"), self.tab_wdg.datatype_combobox_tab1.currentText()))										

	@QtCore.pyqtSlot()	
	def server_init(self):
		if self.server_state == 0:
			try:
				self.serv_nonblocking.start()
				self.host_ip = self.serv_nonblocking.detected_server_ip
				self.tab_wdg.le_addr_tab1.setText("{}".format(self.host_ip))
				self.log_widget.appendPlainText("[{}] server run successful".format(strftime("%H:%M:%S")))	
				self.server_state = 1
				self.tab_wdg.btn_run_server.setText('Shutdown')
				self.tab_wdg.led_status_tab1.toggle()
			except:
				self.log_widget.appendPlainText("[{}] server run failed: \n {}".format(strftime("%H:%M:%S"), traceback.format_exc()))	
				self.server_state = 0
		else:
			try:
				self.serv_nonblocking.stop()
				self.log_widget.appendPlainText("[{}] server shutdown succes: \n {}".format(strftime("%H:%M:%S"), traceback.format_exc()))
				self.server_state = 0
				self.tab_wdg.btn_run_server.setText('Run')
				self.tab_wdg.led_status_tab1.toggle()
			except:
				self.log_widget.appendPlainText("[{}] server shutdown failed: \n {}".format(strftime("%H:%M:%S"), traceback.format_exc()))

	@QtCore.pyqtSlot()
	def server_send_datapacket(self):
		# self.log_widget.appendPlainText("[{}] server send: {}".format(strftime("%H:%M:%S"), '[0x01,0x02,0x01,0x11,0x00,0x01]'))
		try:
			reg_number = int(self.tab_wdg.le_reg_number_tab1.text(),16)
			cl_addr = int(self.tab_wdg.le_client_addr_tab1.text(), 16)
			if self.server_data_type == 0x01:
				self.fixed_packet = [0x02, 0x01, 0x11, 0x00, 0x01, 0x01]  # | our address | server address | cmd | reg hi | reg low | data |
				self.fixed_packet[0] = 0x01 | mark_line 
				self.fixed_packet[1] = cl_addr
				self.fixed_packet[2] = (self.server_cmd << 4) | (self.server_data_type & 0xf)
				self.fixed_packet[3] = (reg_number >> 8) & 0xff
				self.fixed_packet[4] = reg_number & 0xff
				if self.tab_wdg.datamode_combobox_tab1.currentText() == 'Fixed':
					# byte_arr = bytearray.fromhex(self.tab_wdg.le_data_tab1.text())
					byte_arr = int(self.tab_wdg.le_data_tab2.text(),16)
					self.fixed_packet[5] = byte_arr
					self.log_widget.appendPlainText("[{}] data(byte): {}".format(strftime("%H:%M:%S"), self.fixed_packet[5]))
				elif self.tab_wdg.datamode_combobox_tab1.currentText() == 'Random':
					self.fixed_packet[5] = np.random.randint(0, 255)
				elif self.tab_wdg.datamode_combobox_tab1.currentText() == 'List':
					self.fixed_packet[5] = np.random.randint(0, 255)

			elif self.server_data_type == 0x02:
				self.fixed_packet = [0x01, 0x02, 0x12, 0x00, 0x01, 0x00, 0x01]  # | our address | server address | cmd | reg hi | reg low | data |
				self.fixed_packet[0] = 0x01 | mark_line
				self.fixed_packet[1] = cl_addr
				self.fixed_packet[2] = (self.server_cmd << 4) | (self.server_data_type & 0xf)
				self.fixed_packet[3] = (reg_number >> 8) & 0xff
				self.fixed_packet[4] = reg_number & 0xff
				if self.tab_wdg.datamode_combobox_tab1.currentText() == 'Fixed':
					# byte_arr = bytearray.fromhex(self.tab_wdg.le_data_tab2.text())
					byte_arr = int(self.tab_wdg.le_data_tab2.text(),16)
					self.fixed_packet[5] = (byte_arr >> 8) & 0xff
					self.fixed_packet[6] = byte_arr & 0xff
					self.log_widget.appendPlainText("[{}] hex data(short): {}".format(strftime("%H:%M:%S"), byte_arr))
				elif self.tab_wdg.datamode_combobox_tab1.currentText() == 'Random':
					data_rand = np.random.randint(0, 16383)
					self.fixed_packet[5] = (data_rand >> 8) & 0xff
					self.fixed_packet[6] = data_rand & 0xff
				elif self.tab_wdg.datamode_combobox_tab1.currentText() == 'List':
					data_rand = np.random.randint(0, 16383)
					self.fixed_packet[5] = (data_rand >> 8) & 0xff
					self.fixed_packet[6] = data_rand & 0xff

			elif self.server_data_type == 0x03:
				self.fixed_packet = [0x01, 0x02, 0x13, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01]  # | our address | server address | cmd | reg hi | reg low | data |
				
				self.fixed_packet[0] = 0x01 | mark_line
				self.fixed_packet[1] = cl_addr
				self.fixed_packet[2] = (self.server_cmd << 4) | (self.server_data_type & 0xf)
				self.fixed_packet[3] = (reg_number >> 8) & 0xff
				self.fixed_packet[4] = reg_number & 0xff
				if self.tab_wdg.datamode_combobox_tab1.currentText() == 'Fixed':
					byte_arr = int(self.tab_wdg.le_data_tab2.text(),16)
					self.log_widget.appendPlainText("[{}] data(word): {}".format(strftime("%H:%M:%S"), byte_arr))
					self.fixed_packet[5] = (byte_arr >> 24) & 0xff
					self.fixed_packet[6] = (byte_arr >> 16) & 0xff 
					self.fixed_packet[7] = (byte_arr >> 8) & 0xff
					self.fixed_packet[8] = byte_arr & 0xff
				elif self.tab_wdg.datamode_combobox_tab1.currentText() == 'Random':
					data_rand = np.random.randint(0, (2**31)-1)
					self.fixed_packet[5] = (data_rand >> 24) & 0xff
					self.fixed_packet[6] = (data_rand >> 16) & 0xff
					self.fixed_packet[7] = (data_rand >> 8) & 0xff
					self.fixed_packet[8] = (data_rand & 0xff)
					self.log_widget.appendPlainText("[{}] data(word): {:4X}".format(strftime("%H:%M:%S"), data_rand))
				elif self.tab_wdg.datamode_combobox_tab1.currentText() == 'List':
					data_rand = np.random.randint(0, (2**31)-1)
					self.fixed_packet[5] = (data_rand >> 24) & 0xff
					self.fixed_packet[6] = (data_rand >> 16) & 0xff
					self.fixed_packet[7] = (data_rand >> 8) & 0xff
					self.fixed_packet[8] = (data_rand & 0xff)
					self.log_widget.appendPlainText("[{}] data(word): {:4X}".format(strftime("%H:%M:%S"), data_rand))

			elif self.server_data_type == 0x04:
				self.fixed_packet = [0x01, 0x02, 0x14, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04]  # | our address | server address | cmd | reg hi | reg low | data |
				self.fixed_packet[0] = 0x01 | mark_line
				self.fixed_packet[1] = cl_addr
				self.fixed_packet[2] = (self.server_cmd << 4)|(self.server_data_type & 0xf)
				self.fixed_packet[3] = (reg_number >> 8) & 0xff
				self.fixed_packet[4] = reg_number & 0xff
				if self.tab_wdg.datamode_combobox_tab1.currentText() == 'Fixed':
					data_float = float(self.tab_wdg.le_data_tab1.text())
					ba = bytearray(struct.pack("f", data_float)) 
					self.fixed_packet[5] = ba[0]
					self.fixed_packet[6] = ba[1]
					self.fixed_packet[7] = ba[2]
					self.fixed_packet[8] = ba[3]
					self.log_widget.appendPlainText("[{}] data(float): {:02X}{:02X}{:02X}{:02X}({})".format(
						strftime("%H:%M:%S"), ba[0], ba[1], ba[2], ba[3], data_float))
				elif self.tab_wdg.datamode_combobox_tab1.currentText() == 'Random':
					data_float = np.random.ranf()
					ba = bytearray(struct.pack("f", data_float)) 
					self.fixed_packet[5] = ba[0]
					self.fixed_packet[6] = ba[1]
					self.fixed_packet[7] = ba[2]
					self.fixed_packet[8] = ba[3]
					self.log_widget.appendPlainText("[{}] data(float): {:02X}{:02X}{:02X}{:02X}({})".format(
						strftime("%H:%M:%S"), ba[0], ba[1], ba[2], ba[3], data_float))
				elif self.tab_wdg.datamode_combobox_tab1.currentText() == 'List':
					data_float = np.random.ranf()
					ba = bytearray(struct.pack("f", data_float)) 
					self.fixed_packet[5] = ba[0]
					self.fixed_packet[6] = ba[1]
					self.fixed_packet[7] = ba[2]
					self.fixed_packet[8] = ba[3]
					self.log_widget.appendPlainText("[{}] data(float): {:02X}{:02X}{:02X}{:02X}({})".format(
						strftime("%H:%M:%S"), ba[0], ba[1], ba[2], ba[3], data_float))
			if self.server_data_type == 0x05:
				self.fixed_packet = [0x01, 0x02, 0x01, 0x11, 0x00, 0x01]  # | our address | server address | cmd | reg hi | reg low | data |
				self.fixed_packet[0] = 0x01 | mark_line
				self.fixed_packet[1] = cl_addr
				self.fixed_packet[2] = (self.server_cmd << 4)|(self.server_data_type & 0xf)
				self.fixed_packet[3] = (reg_number >> 8) & 0xff
				self.fixed_packet[4] = reg_number & 0xff
				if self.tab_wdg.datamode_combobox_tab1.currentText() == 'Fixed':
					self.fixed_packet[5] = int(self.tab_wdg.le_data_tab1.text())
				elif self.tab_wdg.datamode_combobox_tab1.currentText() == 'Random':
					self.fixed_packet[5] = np.random.random_integers(0, 255)
				elif self.tab_wdg.datamode_combobox_tab1.currentText() == 'List':
					self.fixed_packet[5] = np.random.random_integers(0, 255)

			if int(self.tab_wdg.le_timeout_tab1.text()) != 0:
				self.timer.start(int(self.tab_wdg.le_timeout_tab1.text())*1000)
				self.log_widget.appendPlainText("[{}] multi shot, repeat time: {} sec".format(strftime("%H:%M:%S"), int(self.tab_wdg.le_timeout_tab1.text())))
			else:
				self.timer.stop()
				self.log_widget.appendPlainText("[{}] single shot".format(strftime("%H:%M:%S")))
			print(self.fixed_packet)
			self.socket_log_widget.appendPlainText("[{}] SEND: ".format(strftime("%H:%M:%S")) +''.join('0x{:02X} '.format(a) for a in self.fixed_packet))
			
			self.serv_nonblocking.server_send_data(bytearray(self.fixed_packet))

			#self.client.running = False
			#self.client.s.sendall(bytearray(self.fixed_packet))	
			#data_raw = self.client.s.recv(1024)
			#self.client.running = True
			#self.log_widget.appendPlainText("[{}] recv: {}".format(strftime("%H:%M:%S"), data_raw))
			#self.socket_log_widget.appendPlainText("[{}] RECV: ".format(strftime("%H:%M:%S")) + ''.join('0x{:02X} '.format(a) for a in data_raw)) 
		except:
			self.log_widget.appendPlainText("[{}] RECV: {}".format(strftime("%H:%M:%S"), traceback.format_exc()))
			self.socket_log_widget.appendPlainText("[{}] RECV: TIMEOUT".format(strftime("%H:%M:%S")))


class tabWidgetCustom(QtWidgets.QWidget):
	def __init__(self, parent, widget_width=80, widget_height=30):
		super(QtWidgets.QWidget, self).__init__(parent)
		self.layout = QtWidgets.QVBoxLayout()
		self.__widget_width = widget_width
		self.__widget_height = widget_height
		
		self.value_1_255 = QRegExpValidator(QtCore.QRegExp("1[0-9]{2}|2[0-4][0-9]|25[0-5]|[0-9]|[0-9][0-9]")) #"00[1-9]|0[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]"
		self.value_1_100000 = QRegExpValidator(QtCore.QRegExp("[0-9]{5}"))#QtGui.QIntValidator(1,99999)
		self.tabs = QtWidgets.QTabWidget()
		self.tab1 = QtWidgets.QWidget()#server tab
		self.tab2 = QtWidgets.QWidget()#client tab
		self.tabs.setMinimumSize(350,280)
		self.tabs.resize(350,280)

		self.tabs.addTab(self.tab1, "Server")
		self.tabs.addTab(self.tab2, "Client")

		self.tab1.layout = QtWidgets.QVBoxLayout()
		self.tab1.grid_tab1 = QtWidgets.QGridLayout()

		self.btn_run_server = QtWidgets.QPushButton("Run")
		self.lbl_addr_tab1 = QtWidgets.QLabel("Server IP:")
		self.le_addr_tab1 = QtWidgets.QLineEdit("0.0.0.0")
		self.le_addr_tab1.setReadOnly(True)

		self.led_status_tab1 = LedIndicator(self, color = [[0, 255, 0],[0, 192, 0],[28, 0, 0],[128, 0, 0]])
		self.led_status_tab1.setDisabled(True)

		self.tab1.grid_tab1.addWidget(self.lbl_addr_tab1, 0, 0, 1,1)
		self.tab1.grid_tab1.addWidget(self.le_addr_tab1, 0, 1, 1,1)
		self.tab1.grid_tab1.addWidget(self.led_status_tab1, 0, 2, 1,1, Qt.AlignLeft)

		self.tab1.grid_tab1.addWidget(self.btn_run_server, 1, 0, 1,1)

		self.lbl_client_addr_tab1 = QtWidgets.QLabel("Client:")
		self.le_client_addr_tab1 = QtWidgets.QLineEdit("12")
		self.le_client_addr_tab1.setValidator(QRegExpValidator(QtCore.QRegExp("[a-fA-F0-9]{2}"))) #QRegExpValidator(QtCore.QRegExp("[a-hA-h0-9]{2}"))

		self.lbl_cmd_combobox_tab1 = QtWidgets.QLabel("Command:")
		self.cmd_combobox_tab1 = QtWidgets.QComboBox(self)
		self.cmd_combobox_tab1.addItems(["Write[0x1x]", "Read[0x2x]"])#, "Response[0x6x]", "Notification data change[0x7x]", "Write/read fault[0x5x]"])
		#self.cmd_combobox.setMaximumSize(self.__widget_width,self.__widget_height)
		self.cmd_combobox_tab1.setSizePolicy(QtWidgets.QSizePolicy.Fixed,QtWidgets.QSizePolicy.Fixed)

		self.lbl_datatype_combobox_tab1 = QtWidgets.QLabel("Data type:")
		self.datatype_combobox_tab1 = QtWidgets.QComboBox(self)
		self.datatype_combobox_tab1.addItems(["Byte[I8/U8]", "Short[I16/U16]", "Word[I32/U32]", "Real[Float]", "nByte[Custom]"])
		#self.cmd_combobox.setMaximumSize(self.__widget_width,self.__widget_height)
		self.datatype_combobox_tab1.setSizePolicy(QtWidgets.QSizePolicy.Fixed,QtWidgets.QSizePolicy.Fixed)
		self.datamode_combobox_tab1 = QtWidgets.QComboBox(self)
		self.datamode_combobox_tab1.addItems(["Fixed", "Random", "List"])

		self.lbl_reg_number_tab1 = QtWidgets.QLabel("Reg №:")
		self.le_reg_number_tab1 = QtWidgets.QLineEdit("0001")
		self.le_reg_number_tab1.setValidator(QRegExpValidator(QtCore.QRegExp("[0-9]{4}|[a-fA-F0-9]{4}"))) #QRegExpValidator(QtCore.QRegExp("[a-hA-h0-9]{2}"))

		self.lbl_data_tab1 = QtWidgets.QLabel("Data:")
		self.le_data_tab1 = QtWidgets.QLineEdit("00")
		self.le_data_tab1.setValidator(QRegExpValidator(QtCore.QRegExp("[0-9]{2}|[a-fA-F0-9]{2}"))) #QRegExpValidator(QtCore.QRegExp("[a-hA-h0-9]{2}"))
		self.lbl_data_len_tab1 = QtWidgets.QLabel("Length(Bytes):")
		self.le_data_len_tab1 = QtWidgets.QLineEdit("1")
		self.le_data_len_tab1.setValidator(QtGui.QIntValidator(1,99)) #setValidator(QtGui.QIntValidator(1,99))

		self.btn_send_data_tab1 = QtWidgets.QPushButton("Send")
		self.lbl_timeout_tab1 = QtWidgets.QLabel("Repeat time[sec]:")
		self.le_timeout_tab1 = QtWidgets.QLineEdit("0")
		self.le_timeout_tab1.setValidator(QtGui.QIntValidator(1,999))

		self.tab1.grid_tab1.addWidget(self.lbl_client_addr_tab1, 2, 0)
		self.tab1.grid_tab1.addWidget(self.le_client_addr_tab1, 2, 1, 1, 1)

		self.tab1.grid_tab1.addWidget(self.lbl_cmd_combobox_tab1, 3, 0)
		self.tab1.grid_tab1.addWidget(self.cmd_combobox_tab1, 3, 1, 1, 3)
		self.tab1.grid_tab1.addWidget(self.lbl_datatype_combobox_tab1, 4,0)
		self.tab1.grid_tab1.addWidget(self.datatype_combobox_tab1, 4, 1)	
		self.tab1.grid_tab1.addWidget(self.datamode_combobox_tab1, 4, 2)	

		self.tab1.grid_tab1.addWidget(self.lbl_reg_number_tab1, 5,0)
		self.tab1.grid_tab1.addWidget(self.le_reg_number_tab1, 5, 1, 1, 1)
		self.tab1.grid_tab1.addWidget(self.lbl_data_tab1, 6,0)
		self.tab1.grid_tab1.addWidget(self.le_data_tab1, 6, 1, 1, 2)

		self.tab1.grid_tab1.addWidget(self.btn_send_data_tab1, 7, 0,1,1)
		self.tab1.grid_tab1.addWidget(self.lbl_timeout_tab1, 7,2,1,1)
		self.tab1.grid_tab1.addWidget(self.le_timeout_tab1, 7,3,1,1)

		self.tab1.grid_tab1.addWidget(QtWidgets.QLabel(""), 8, 0)
		self.tab1.layout.insertLayout(0, self.tab1.grid_tab1)
		self.tab1.layout.addWidget(QtWidgets.QLabel(""), 1)
		self.tab1.setLayout(self.tab1.layout)

		self.tab2.layout = QtWidgets.QVBoxLayout(self)
		self.tab2.grid_tab2 = QtWidgets.QGridLayout()
		self.btn_connect_to_server = QtWidgets.QPushButton("Connect")
		self.lbl_addr_tab2 = QtWidgets.QLabel("Server IP:")
		self.le_addr_tab2 = QtWidgets.QLineEdit("192.168.0.2")

		self.lbl_port_tab2 = QtWidgets.QLabel("PORT:")
		self.le_port_tab2 = QtWidgets.QLineEdit("9110")
		self.le_port_tab2.setValidator(self.value_1_100000)

		self.lbl_inner_addr_tab2 = QtWidgets.QLabel("Protocol \n Address:")
		self.le_inner_addr_tab2 = QtWidgets.QLineEdit("12")
		self.le_inner_addr_tab2.setValidator(QRegExpValidator(QtCore.QRegExp("[a-fA-F0-9]{2}")))

		self.tab2.grid_tab2.addWidget(self.lbl_addr_tab2, 0, 0)
		self.tab2.grid_tab2.addWidget(self.le_addr_tab2, 1, 0)
		self.tab2.grid_tab2.addWidget(self.lbl_port_tab2, 0, 1)
		self.tab2.grid_tab2.addWidget(self.le_port_tab2, 1, 1)		
		self.tab2.grid_tab2.addWidget(self.btn_connect_to_server, 2, 0)
		self.tab2.grid_tab2.addWidget(self.lbl_inner_addr_tab2, 0,2)
		self.tab2.grid_tab2.addWidget(self.le_inner_addr_tab2, 1, 2)

		self.led_client_status = LedIndicator(self,color = [[0, 255, 0],[0, 192, 0],[28, 0, 0],[128, 0, 0]])
		self.led_client_status.setDisabled(True)
		self.tab2.grid_tab2.addWidget(self.led_client_status, 2, 1, 1,1, Qt.AlignLeft)

		self.lbl_cmd_combobox = QtWidgets.QLabel("Command:")
		self.cmd_combobox = QtWidgets.QComboBox(self)
		self.cmd_combobox.addItems(["Write[0x1x]", "Read[0x2x]"])#, "Response[0x6x]", "Notification data change[0x7x]", "Write/read fault[0x5x]"])
		#self.cmd_combobox.setMaximumSize(self.__widget_width,self.__widget_height)
		self.cmd_combobox.setSizePolicy(QtWidgets.QSizePolicy.Fixed,QtWidgets.QSizePolicy.Fixed)

		self.lbl_datatype_combobox = QtWidgets.QLabel("Data type:")
		self.datatype_combobox = QtWidgets.QComboBox(self)
		self.datatype_combobox.addItems(["Byte[I8/U8]", "Short[I16/U16]", "Word[I32/U32]", "Real[Float]", "nByte[Custom]"])
		#self.cmd_combobox.setMaximumSize(self.__widget_width,self.__widget_height)
		self.datatype_combobox.setSizePolicy(QtWidgets.QSizePolicy.Fixed,QtWidgets.QSizePolicy.Fixed)
		self.datamode_combobox = QtWidgets.QComboBox(self)
		self.datamode_combobox.addItems(["Fixed", "Random", "List"])

		self.lbl_reg_number_tab2 = QtWidgets.QLabel("Reg №:")
		self.le_reg_number_tab2 = QtWidgets.QLineEdit("0001")
		self.le_reg_number_tab2.setValidator(QRegExpValidator(QtCore.QRegExp("[0-9]{4}|[a-fA-F0-9]{4}"))) #QRegExpValidator(QtCore.QRegExp("[a-hA-h0-9]{2}"))

		self.lbl_data_tab2 = QtWidgets.QLabel("Data:")
		self.le_data_tab2 = QtWidgets.QLineEdit("00")
		self.le_data_tab2.setValidator(QRegExpValidator(QtCore.QRegExp("[0-9]{2}|[a-fA-F0-9]{2}"))) #QRegExpValidator(QtCore.QRegExp("[a-hA-h0-9]{2}"))
		self.lbl_data_len_tab2 = QtWidgets.QLabel("Length(Bytes):")
		self.le_data_len_tab2 = QtWidgets.QLineEdit("1")
		self.le_data_len_tab2.setValidator(QtGui.QIntValidator(1,99)) #setValidator(QtGui.QIntValidator(1,99))

		self.btn_send_data_tab2 = QtWidgets.QPushButton("Send")
		self.lbl_timeout_tab2 = QtWidgets.QLabel("Repeat time[sec]:")
		self.le_timeout_tab2 = QtWidgets.QLineEdit("0")
		self.le_timeout_tab2.setValidator(QtGui.QIntValidator(1,999))

		self.tab2.grid_tab2.addWidget(self.lbl_cmd_combobox, 3, 0)
		self.tab2.grid_tab2.addWidget(self.cmd_combobox, 3, 1, 1, 3)
		self.tab2.grid_tab2.addWidget(self.lbl_datatype_combobox, 4,0)
		self.tab2.grid_tab2.addWidget(self.datatype_combobox, 4, 1)	
		self.tab2.grid_tab2.addWidget(self.datamode_combobox, 4, 2)	

		self.tab2.grid_tab2.addWidget(self.lbl_reg_number_tab2, 5,0)
		self.tab2.grid_tab2.addWidget(self.le_reg_number_tab2, 5, 1, 1, 1)
		self.tab2.grid_tab2.addWidget(self.lbl_data_tab2, 6,0)
		self.tab2.grid_tab2.addWidget(self.le_data_tab2, 6, 1, 1, 2)

		self.tab2.grid_tab2.addWidget(self.btn_send_data_tab2, 7, 0,1,1)
		self.tab2.grid_tab2.addWidget(self.lbl_timeout_tab2, 7,2,1,1)
		self.tab2.grid_tab2.addWidget(self.le_timeout_tab2, 7,3,1,1)

		last_row = 7
		self.tab2.grid_tab2.addWidget(QtWidgets.QLabel(""), last_row+1, 0)
		self.tab2.layout.insertLayout(0, self.tab2.grid_tab2)
		self.tab2.layout.addWidget(QtWidgets.QLabel(""), 1)
		self.tab2.setLayout(self.tab2.layout)

		self.layout.addWidget(self.tabs)
		self.setLayout(self.layout)

	@QtCore.pyqtSlot()
	def on_connect_to_server(self):
		try:
			if self.btn_connect_to_server.text() == "Disconnect":
				self.btn_connect_to_server.setText("Connect")
				self.led_client_status.toggle()
				self.le_addr_tab2.setReadOnly(False)
				self.le_port_tab2.setReadOnly(False)
				self.le_inner_addr_tab2.setReadOnly(False)
			else:
				self.btn_connect_to_server.setText("Disconnect")
				self.led_client_status.toggle()
				self.le_addr_tab2.setReadOnly(True)
				self.le_port_tab2.setReadOnly(True)
				self.le_inner_addr_tab2.setReadOnly(True)
		except:			
			error_traceback_str = traceback.format_exc()
			traceback.print_exc()

	@QtCore.pyqtSlot()
	def on_run_server(self):
		try:
			if self.btn_run_server.text() == "Stop server":
				self.btn_run_server.setText("Run server")
			else:
				self.btn_run_server.setText("Stop server")
		except:
			error_traceback_str = traceback.format_exc()
			traceback.print_exc()


class ServerThread(QtCore.QThread):
	status_signal = QtCore.pyqtSignal(str)
	status_packet = QtCore.pyqtSignal(str)
	data = QtCore.pyqtSignal(np.ndarray)
	progress = QtCore.pyqtSignal(int)

	def __init__(self, server_ip='', server_port=9110):
		# QtCore.QThread.__init__(self, parent)
		super().__init__()
		self.running = False

		#'Server IP: {}'.format(socket.gethostbyname(socket.gethostname()))
		self.detected_server_ip = socket.gethostbyname(socket.gethostname())
		self.server_port_inner = server_port
		self.server_ip_inner = server_ip
		self.data_type = 0x01 #1-byte 2-short 3-word 4-float 5 - dynamic len
		self.command_type = 0x01 #cmd 1-write 2-read 6-response 7 - notification 5 - error read/write 
		self.data_len = 0x01 #1-byte 2-short 4-word/short
		self.data = 0x00 
		self.address = 0x12 #client network address
		self.data_send_asyo = ''

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
		self.status_signal.emit("accepted connection from {}".format(addr))
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
				print('server recv_data: '+''.join('0x{:02X} '.format(a) for a in recv_data))
			else:
				print('server closing connection to', data.addr)
				self.status_signal.emit("server closing connection to {}".format(data.addr))
				sel.unregister(sock)
				sock.close()
		if mask & selectors.EVENT_WRITE:
			if data.outb:
				# print('sending: ', repr(data.outb), 'to', data.addr)
				self.status_signal.emit("sending: {}, to {}".format(data.outb, data.addr))

				data_ts = self.packet_proccessing(data.outb)
				print('server event_write: {}'.format(data_ts))
				if (data_ts[0] == 0) and (data_ts[1] == 0):
					self.status_signal.emit("skip response")
					data.outb = b''
				else:
					self.status_signal.emit("sending: {}".format(repr(data.outb),data.addr))
					self.status_packet.emit("SEND         : "+''.join('0x{:02X} '.format(a) for a in data_ts))
					sent = sock.send(bytearray(data_ts))  # Should be ready to write
					data.outb = b''
			else:
				if self.data_send_asyo:
					print("server asyo send data: {}".format(self.data_send_asyo))
					sent = sock.send(self.data_send_asyo)
					self.data_send_asyo = ''

	# TODO add data_packet.py classes
	def packet_proccessing(self, input_data):
		data_response = list()
		# | our address | server address | cmd | reg hi | reg low | data |
		# print('data_processing: '+''.join('0x{:02X} '.format(a) for a in input_data))
		if input_data[0] == 0x3d and input_data[1] == 0xec :
			self.status_signal.emit("byte data type, lenght: {}".format(len(input_data)))
			self.status_packet.emit("HANDSHAKE client: "+''.join('0x{:02X} '.format(a) for a in input_data))
			print('server recv handshake: {}'.format(input_data))
			data_response = [0]*4
			data_response[0] = 0xDA
			data_response[1] = 0xBA
			data_response[2] = 0x01  # protocol version
			data_response[3] = 0x01  # net address
			print('server send handshake: {}'.format(data_response))

		elif ((input_data[1]) & 0x0f) == 0x01 and (((input_data[2]) & 0xf0) == 0x10  or ((input_data[2]) & 0xf0) == 0x20):
			# print("byte data type, lenght: {}".format(len(input_data)))
			self.status_signal.emit("byte data type, lenght: {}".format(len(input_data)))
			self.status_packet.emit("RECEIVED: "+''.join('0x{:02X} '.format(a) for a in input_data))
			print("server write/read in")
			if (input_data[2] & 0x0f) == 0x01:
				data_response = [0]*6
				data_response[0] = input_data[0]
				data_response[1] = 0x11
				data_response[2] = (input_data[2] & 0x0f) | 0x50
				try:
					for a in range(len(input_data)-3):				
						data_response[a+3] = input_data[a+3]	
				except:
					print(input_data)			
			elif (input_data[2] & 0x0f) == 0x02:
				data_response = [0]*7
				data_response[0] = input_data[0]
				data_response[1] = 0x11
				data_response[2] = (input_data[2] & 0x0f) | 0x50
				for a in range(len(input_data)-3):				
					data_response[a+3] = input_data[a+3]				
			elif (input_data[2] & 0x0f) == 0x03:
				data_response = [0]*9
				data_response[0] = input_data[0]
				data_response[1] = 0x11
				data_response[2] = (input_data[2]&0x0f) | 0x50
				for a in range(len(input_data)-3):				
					data_response[a+3] = input_data[a+3]							
			elif (input_data[2] & 0x0f) == 0x04:
				data_response = [0]*9
				data_response[0] = input_data[0]
				data_response[1] = 0x11
				data_response[2] = (input_data[2]&0x0f) | 0x50
				for a in range(len(input_data)-3):				
					data_response[a+3] = input_data[a+3]							
			elif (input_data[2] & 0x0f) == 0x05:
				data_response = [0]*len(input_data)				
				data_response[0] = input_data[0]
				data_response[1] = 0x11
				data_response[2] = (input_data[2] & 0x0f) | 0x50
				for a in range(len(input_data)-3):				
					data_response[a+3] = input_data[a+3]
			else:
				self.status_signal.emit("data type unknown: {}, cmd byte: {}".format((input_data[2]&0x0f), input_data[2]))
				print('server data type unknown: {:2X}'.format(input_data))
		else:
			# print("packet pass{}".format(input_data))
			self.status_signal.emit("packet pass: {}".format(input_data))
			data_response = [0]*10
		return data_response


class ClientThread(QtCore.QThread):
	def __init__(self, connect_ip = '0.0.0.0', connect_port = '0', client_addr = '2'):
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

	def run(self):
		self.running = True
		self.asyn_recv_flag = True
		while self.running:
			if self.asyn_recv_flag == True:
				try:
					self.asyn_recv_raw = self.s.recv(100)
				except:
					pass
				if self.asyn_recv_raw:
					print("client received: {}".format(self.asyn_recv_raw))
					data_to_send = self.packet_proccessing(self.asyn_recv_raw)
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
			recv_data = sock.recv(1024)
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
		try:
			self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.s.settimeout(0.5)	
			#self.s.setblocking(False)
			self.s.connect((ip, port))

			#self.events = selectors.EVENT_READ | selectors.EVENT_WRITE
			#data = types.SimpleNamespace(inb=b'', outb=b'')
			#sel_client.register(self.s, self.events, data=data)

			self.s.send(self.client_handshake_bytearray)
			data_raw = self.s.recv(1024)
			if data_raw[0] == 0xDA and data_raw[1] == 0xBA:
				print('client Server handshake: {}'.format(data_raw))
			else:
				print('client unknown response: {}'.format(data_raw))
		except:
			pass

	def close_connection(self):
		self.s.close()

	def process_raw(self, raw_data):
		print(raw_data)

	def packet_proccessing(self, input_data):
		data_response = list()
		#| our address | server address | cmd | reg hi | reg low | data |
		if input_data[0] == 0xda and input_data[1] == 0xba :
			#self.status_signal.emit("byte data type, lenght: {}".format(len(input_data)))
			#self.status_packet.emit("HANDSHAKE client: "+''.join('0x{:02X} '.format(a) for a in input_data))
			data_response = [0]*4
			data_response[0] = 0xDA
			data_response[1] = 0xBA
			data_response[2] = 0x01 #protocol version
			data_response[3] = 0x01 #net address
		elif ((input_data[1])&0x0f) == 0x02:
			#self.status_signal.emit("byte data type, lenght: {}".format(len(input_data)))
			#self.status_packet.emit("RECEIVED: "+''.join('0x{:02X} '.format(a) for a in input_data))
			if (input_data[2]&0x0f) == 0x01:
				data_response = [0]*6
				data_response[0] = self.out_inner_address
				data_response[1] = input_data[0]
				data_response[2] = (input_data[2]&0x0f)|0x60
				for a in range(len(input_data)-3):				
					data_response[a+3] = input_data[a+3]				
			elif (input_data[2]&0x0f) == 0x02:
				data_response = [0]*7
				data_response[0] = self.out_inner_address
				data_response[1] = input_data[0]
				data_response[2] = (input_data[2]&0x0f)|0x60
				for a in range(len(input_data)-3):				
					data_response[a+3] = input_data[a+3]				
			elif (input_data[2]&0x0f) == 0x03:
				data_response = [0]*9
				data_response[0] = self.out_inner_address
				data_response[1] = input_data[0]
				data_response[2] = (input_data[2]&0x0f)|0x60
				for a in range(len(input_data)-3):				
					data_response[a+3] = input_data[a+3]							
			elif (input_data[2]&0x0f) == 0x04:
				data_response = [0]*9
				data_response[0] = self.out_inner_address
				data_response[1] = input_data[0]
				data_response[2] = (input_data[2]&0x0f)|0x60
				for a in range(len(input_data)-3):				
					data_response[a+3] = input_data[a+3]							
			elif (input_data[2]&0x0f) == 0x05:
				data_response = [0]*len(input_data)				
				data_response[0] = self.out_inner_address
				data_response[1] = input_data[0]
				data_response[2] = (input_data[2]&0x0f)|0x60
				for a in range(len(input_data)-3):				
					data_response[a+3] = input_data[a+3]
			else:
				pass
				#self.status_signal.emit("data type unknown: {}, cmd byte: {}".format((input_data[2]&0x0f), input_data[2]))
		else:
			#print("packet pass{}".format(input_data))
			#self.status_signal.emit("packet pass: {}".format(input_data))
			data_response = [0]*10
		return data_response		
	def client_reseive_message(self):
		receive_bytearray = ''
		receive_bytearray = self.s.recv(1024)
		return receive_bytearray


class rawSocket:
	#https://docs.python.org/3/library/socket.html
	def __init__(self, socket_type = 'Server', client_bus_serialnumber = 0x02):
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
		#with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as self.s:
		try:
			self.s.settimeout(10)#sec
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
		self.s.settimeout(0.1)#sec
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

	def client_reseive_message(self):
		receive_bytearray = ''
		receive_bytearray = self.s.recv(1024)
		return receive_bytearray

	def server_scan_all(self):
		self.s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
		print(self.s.recvfrom(65565))
		self.s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)


class LedIndicator(QtWidgets.QAbstractButton):
	scaledSize = 1000.0

	def __init__(self, parent=None, color = [[0, 255, 0],[0, 192, 0],[0, 28, 0],[0, 128, 0]]):
		QtWidgets.QAbstractButton.__init__(self, parent)

		self.setMinimumSize(24, 24)
		self.setCheckable(True)

		# Green
		self.on_color_1 = QtGui.QColor(color[0][0],color[0][1],color[0][2])
		self.on_color_2 = QtGui.QColor(color[1][0],color[1][1],color[1][2])
		self.off_color_1 = QtGui.QColor(color[2][0],color[2][1],color[2][2])
		self.off_color_2 = QtGui.QColor(color[3][0],color[3][1],color[3][2])

	def resizeEvent(self, QResizeEvent):
		self.update()

	def paintEvent(self, QPaintEvent):
		realSize = min(self.width(), self.height())

		painter = QtGui.QPainter(self)
		pen = QtGui.QPen(Qt.black)
		pen.setWidth(1)

		painter.setRenderHint(QtGui.QPainter.Antialiasing)
		painter.translate(self.width() / 2, self.height() / 2)
		painter.scale(realSize / self.scaledSize, realSize / self.scaledSize)

		gradient = QtGui.QRadialGradient(QtCore.QPointF(-500, -500), 1500, QtCore.QPointF(-500, -500))
		gradient.setColorAt(0, QtGui.QColor(224, 224, 224))
		gradient.setColorAt(1, QtGui.QColor(28, 28, 28))
		painter.setPen(pen)
		painter.setBrush(QtGui.QBrush(gradient))
		painter.drawEllipse(QtCore.QPointF(0, 0), 500, 500)

		gradient = QtGui.QRadialGradient(QtCore.QPointF(500, 500), 1500, QtCore.QPointF(500, 500))
		gradient.setColorAt(0, QtGui.QColor(224, 224, 224))
		gradient.setColorAt(1, QtGui.QColor(28, 28, 28))
		painter.setPen(pen)
		painter.setBrush(QtGui.QBrush(gradient))
		painter.drawEllipse(QtCore.QPointF(0, 0), 450, 450)

		painter.setPen(pen)
		if self.isChecked():
			gradient = QtGui.QRadialGradient(QtCore.QPointF(-500, -500), 1500, QtCore.QPointF(-500, -500))
			gradient.setColorAt(0, self.on_color_1)
			gradient.setColorAt(1, self.on_color_2)
		else:
			gradient = QtGui.QRadialGradient(QtCore.QPointF(500, 500), 1500, QtCore.QPointF(500, 500))
			gradient.setColorAt(0, self.off_color_1)
			gradient.setColorAt(1, self.off_color_2)

		painter.setBrush(gradient)
		painter.drawEllipse(QtCore.QPointF(0, 0), 400, 400)

	@QtCore.pyqtProperty(QtGui.QColor)
	def onColor1(self):
		return self.on_color_1

	@onColor1.setter
	def onColor1(self, color):
		self.on_color_1 = color

	@QtCore.pyqtProperty(QtGui.QColor)
	def onColor2(self):
		return self.on_color_2

	@onColor2.setter
	def onColor2(self, color):
		self.on_color_2 = color

	@QtCore.pyqtProperty(QtGui.QColor)
	def offColor1(self):
		return self.off_color_1

	@offColor1.setter
	def offColor1(self, color):
		self.off_color_1 = color

	@QtCore.pyqtProperty(QtGui.QColor)
	def offColor2(self):
		return self.off_color_2

	@offColor2.setter
	def offColor2(self, color):
		self.off_color_2 = color


if __name__ == '__main__':
	import sys
	import time, math

	app =QtWidgets.QApplication(sys.argv)
	ex = CommonWindow()
	ex.setFont(QtGui.QFont('Arial', 9))#, QtGui.QFont.Bold
	ex.setWindowTitle("markConnection v{}".format(__version__))
	#app.setStyle('Fusion')
	app.setStyleSheet ( qdarkstyle . load_stylesheet ())
	#ex.setWindowFlags(ex.windowFlags() | QtCore.Qt.FramelessWindowHint)
	#ex.comport_combo.addItems(serial_ports())
	#ex.setFixedSize(500,400)
	#ex.resize(300,200)
	ex.adjustSize()
	#ico = QtGui.QIcon("icon.png")
	#ex.setWindowIcon(ico)#icon for window only
	#app.setWindowIcon(ico)#icon for application
	#if (sys.flags.interactive != 1) or not hasattr(QtCore, 'PYQT_VERSION'):
	#    	QtGui.QApplication.instance().exec_()
	ex.show()
	sys.exit(app.exec_())#run the cycle of processing the events