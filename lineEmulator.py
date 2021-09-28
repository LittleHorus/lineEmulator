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
import pathlib
from tab_widget import TabWidgetCustom
from device_settings_from_xml import XmlDataLoader
from client_thread import ClientThread
from server_thread import ServerThread

__version__ = '1.0.3'

mark_line = 0x10


class CommonWindow(QtWidgets.QWidget):
	"""Класс основного окна программы"""
	def __init__(self, parent=None):
		# QtWidgets.QMainWindow.__init__(self, parent)
		super().__init__(parent)
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

		self.tab_wdg = TabWidgetCustom(self, horizontal_size, vertical_size)

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
		self.tab_wdg.tabs.setCurrentIndex(0)

		self.timer = QTimer()
		self.timer.timeout.connect(self.on_timer_interrupt)

		self.timer_client = QTimer()
		self.timer_client.timeout.connect(self.on_timer_client_interrupt)

		xmlData = XmlDataLoader()
		xmlData.xml_load("{}\\data\\plc_device.xml".format(pathlib.Path(__file__).parent.resolve()))

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