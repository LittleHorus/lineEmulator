#!/usr/bin/python3
# -*- coding: utf-8 -*-

from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QRegExpValidator
from led_widget import LedIndicator


class TabWidgetCustom(QtWidgets.QWidget):
    def __init__(self, parent, widget_width=80, widget_height=30):
        # super(QtWidgets.QWidget, self).__init__(parent)
        super().__init__(parent)
        self.layout = QtWidgets.QVBoxLayout()
        self.__widget_width = widget_width
        self.__widget_height = widget_height

        self.value_1_255 = QRegExpValidator(QtCore.QRegExp
            ("1[0-9]{2}|2[0-4][0-9]|25[0-5]|[0-9]|[0-9][0-9]"))  # "00[1-9]|0[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]"
        self.value_1_100000 = QRegExpValidator(QtCore.QRegExp("[0-9]{5}"))  # QtGui.QIntValidator(1,99999)
        self.tabs = QtWidgets.QTabWidget()
        self.tab1 = QtWidgets.QWidget()  # server tab
        self.tab2 = QtWidgets.QWidget()  # client tab
        self.tabs.setMinimumSize(350, 280)
        self.tabs.resize(350, 280)

        self.tabs.addTab(self.tab1, "Server")
        self.tabs.addTab(self.tab2, "Client")

        self.tab1.layout = QtWidgets.QVBoxLayout()
        self.tab1.grid_tab1 = QtWidgets.QGridLayout()

        self.btn_run_server = QtWidgets.QPushButton("Run")
        self.lbl_addr_tab1 = QtWidgets.QLabel("Server IP:")
        self.le_addr_tab1 = QtWidgets.QLineEdit("0.0.0.0")
        self.le_addr_tab1.setReadOnly(True)

        self.led_status_tab1 = LedIndicator(self, color=[[0, 255, 0], [0, 192, 0], [28, 0, 0], [128, 0, 0]])
        self.led_status_tab1.setDisabled(True)

        self.tab1.grid_tab1.addWidget(self.lbl_addr_tab1, 0, 0, 1, 1)
        self.tab1.grid_tab1.addWidget(self.le_addr_tab1, 0, 1, 1, 1)
        self.tab1.grid_tab1.addWidget(self.led_status_tab1, 0, 2, 1, 1, Qt.AlignLeft)

        self.tab1.grid_tab1.addWidget(self.btn_run_server, 1, 0, 1, 1)

        self.lbl_client_addr_tab1 = QtWidgets.QLabel("Client:")
        self.le_client_addr_tab1 = QtWidgets.QLineEdit("12")
        self.le_client_addr_tab1.setValidator \
            (QRegExpValidator(QtCore.QRegExp("[a-fA-F0-9]{2}")))

        self.lbl_cmd_combobox_tab1 = QtWidgets.QLabel("Command:")
        self.cmd_combobox_tab1 = QtWidgets.QComboBox(self)
        self.cmd_combobox_tab1.addItems(["Write[0x1x]", "Read[0x2x]"])
        # , "Response[0x6x]", "Notification data change[0x7x]", "Write/read fault[0x5x]"])
        # self.cmd_combobox.setMaximumSize(self.__widget_width,self.__widget_height)
        self.cmd_combobox_tab1.setSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)

        self.lbl_datatype_combobox_tab1 = QtWidgets.QLabel("Data type:")
        self.datatype_combobox_tab1 = QtWidgets.QComboBox(self)
        self.datatype_combobox_tab1.addItems \
            (["Byte[I8/U8]", "Short[I16/U16]", "Word[I32/U32]", "Real[Float]", "nByte[Custom]"])
        # self.cmd_combobox.setMaximumSize(self.__widget_width,self.__widget_height)
        self.datatype_combobox_tab1.setSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        self.datamode_combobox_tab1 = QtWidgets.QComboBox(self)
        self.datamode_combobox_tab1.addItems(["Fixed", "Random", "List"])

        self.lbl_reg_number_tab1 = QtWidgets.QLabel("Reg №:")
        self.le_reg_number_tab1 = QtWidgets.QLineEdit("0001")
        self.le_reg_number_tab1.setValidator(QRegExpValidator
            (QtCore.QRegExp("[0-9]{4}|[a-fA-F0-9]{4}")))  # QRegExpValidator(QtCore.QRegExp("[a-hA-h0-9]{2}"))

        self.lbl_data_tab1 = QtWidgets.QLabel("Data:")
        self.le_data_tab1 = QtWidgets.QLineEdit("00")
        self.le_data_tab1.setValidator(QRegExpValidator
            (QtCore.QRegExp("[0-9]{2}|[a-fA-F0-9]{2}")))  # QRegExpValidator(QtCore.QRegExp("[a-hA-h0-9]{2}"))
        self.lbl_data_len_tab1 = QtWidgets.QLabel("Length(Bytes):")
        self.le_data_len_tab1 = QtWidgets.QLineEdit("1")
        self.le_data_len_tab1.setValidator(QtGui.QIntValidator(1, 99))  # setValidator(QtGui.QIntValidator(1,99))

        self.btn_send_data_tab1 = QtWidgets.QPushButton("Send")
        self.lbl_timeout_tab1 = QtWidgets.QLabel("Repeat time[sec]:")
        self.le_timeout_tab1 = QtWidgets.QLineEdit("0")
        self.le_timeout_tab1.setValidator(QtGui.QIntValidator(1, 999))

        self.tab1.grid_tab1.addWidget(self.lbl_client_addr_tab1, 2, 0)
        self.tab1.grid_tab1.addWidget(self.le_client_addr_tab1, 2, 1, 1, 1)

        self.tab1.grid_tab1.addWidget(self.lbl_cmd_combobox_tab1, 3, 0)
        self.tab1.grid_tab1.addWidget(self.cmd_combobox_tab1, 3, 1, 1, 3)
        self.tab1.grid_tab1.addWidget(self.lbl_datatype_combobox_tab1, 4, 0)
        self.tab1.grid_tab1.addWidget(self.datatype_combobox_tab1, 4, 1)
        self.tab1.grid_tab1.addWidget(self.datamode_combobox_tab1, 4, 2)

        self.tab1.grid_tab1.addWidget(self.lbl_reg_number_tab1, 5, 0)
        self.tab1.grid_tab1.addWidget(self.le_reg_number_tab1, 5, 1, 1, 1)
        self.tab1.grid_tab1.addWidget(self.lbl_data_tab1, 6, 0)
        self.tab1.grid_tab1.addWidget(self.le_data_tab1, 6, 1, 1, 2)

        self.tab1.grid_tab1.addWidget(self.btn_send_data_tab1, 7, 0, 1, 1)
        self.tab1.grid_tab1.addWidget(self.lbl_timeout_tab1, 7, 2, 1, 1)
        self.tab1.grid_tab1.addWidget(self.le_timeout_tab1, 7, 3, 1, 1)

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
        self.tab2.grid_tab2.addWidget(self.lbl_inner_addr_tab2, 0, 2)
        self.tab2.grid_tab2.addWidget(self.le_inner_addr_tab2, 1, 2)

        self.led_client_status = LedIndicator(self, color=[[0, 255, 0], [0, 192, 0], [28, 0, 0], [128, 0, 0]])
        self.led_client_status.setDisabled(True)
        self.tab2.grid_tab2.addWidget(self.led_client_status, 2, 1, 1, 1, Qt.AlignLeft)

        self.lbl_cmd_combobox = QtWidgets.QLabel("Command:")
        self.cmd_combobox = QtWidgets.QComboBox(self)
        self.cmd_combobox.addItems(["Write[0x1x]", "Read[0x2x]"]  )  # , "Response[0x6x]", "Notification data change[0x7x]", "Write/read fault[0x5x]"])
        # self.cmd_combobox.setMaximumSize(self.__widget_width,self.__widget_height)
        self.cmd_combobox.setSizePolicy(QtWidgets.QSizePolicy.Fixed ,QtWidgets.QSizePolicy.Fixed)

        self.lbl_datatype_combobox = QtWidgets.QLabel("Data type:")
        self.datatype_combobox = QtWidgets.QComboBox(self)
        self.datatype_combobox.addItems \
            (["Byte[I8/U8]", "Short[I16/U16]", "Word[I32/U32]", "Real[Float]", "nByte[Custom]"])
        # self.cmd_combobox.setMaximumSize(self.__widget_width,self.__widget_height)
        self.datatype_combobox.setSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        self.datamode_combobox = QtWidgets.QComboBox(self)
        self.datamode_combobox.addItems(["Fixed", "Random", "List"])

        self.lbl_reg_number_tab2 = QtWidgets.QLabel("Reg №:")
        self.le_reg_number_tab2 = QtWidgets.QLineEdit("0001")
        self.le_reg_number_tab2.setValidator(QRegExpValidator
            (QtCore.QRegExp("[0-9]{4}|[a-fA-F0-9]{4}")))  # QRegExpValidator(QtCore.QRegExp("[a-hA-h0-9]{2}"))

        self.lbl_data_tab2 = QtWidgets.QLabel("Data:")
        self.le_data_tab2 = QtWidgets.QLineEdit("00")
        self.le_data_tab2.setValidator(QRegExpValidator
            (QtCore.QRegExp("[0-9]{2}|[a-fA-F0-9]{2}")))  # QRegExpValidator(QtCore.QRegExp("[a-hA-h0-9]{2}"))
        self.lbl_data_len_tab2 = QtWidgets.QLabel("Length(Bytes):")
        self.le_data_len_tab2 = QtWidgets.QLineEdit("1")
        self.le_data_len_tab2.setValidator(QtGui.QIntValidator(1, 99))  # setValidator(QtGui.QIntValidator(1,99))

        self.btn_send_data_tab2 = QtWidgets.QPushButton("Send")
        self.lbl_timeout_tab2 = QtWidgets.QLabel("Repeat time[sec]:")
        self.le_timeout_tab2 = QtWidgets.QLineEdit("0")
        self.le_timeout_tab2.setValidator(QtGui.QIntValidator(1, 999))

        self.tab2.grid_tab2.addWidget(self.lbl_cmd_combobox, 3, 0)
        self.tab2.grid_tab2.addWidget(self.cmd_combobox, 3, 1, 1, 3)
        self.tab2.grid_tab2.addWidget(self.lbl_datatype_combobox, 4, 0)
        self.tab2.grid_tab2.addWidget(self.datatype_combobox, 4, 1)
        self.tab2.grid_tab2.addWidget(self.datamode_combobox, 4, 2)

        self.tab2.grid_tab2.addWidget(self.lbl_reg_number_tab2, 5, 0)
        self.tab2.grid_tab2.addWidget(self.le_reg_number_tab2, 5, 1, 1, 1)
        self.tab2.grid_tab2.addWidget(self.lbl_data_tab2, 6, 0)
        self.tab2.grid_tab2.addWidget(self.le_data_tab2, 6, 1, 1, 2)

        self.tab2.grid_tab2.addWidget(self.btn_send_data_tab2, 7, 0, 1, 1)
        self.tab2.grid_tab2.addWidget(self.lbl_timeout_tab2, 7, 2, 1, 1)
        self.tab2.grid_tab2.addWidget(self.le_timeout_tab2, 7, 3, 1, 1)

        last_row = 7
        self.tab2.grid_tab2.addWidget(QtWidgets.QLabel(""), last_row+1, 0)
        self.tab2.layout.insertLayout(0, self.tab2.grid_tab2)
        self.tab2.layout.addWidget(QtWidgets.QLabel(""), 1)
        self.tab2.setLayout(self.tab2.layout)

        self.layout.addWidget(self.tabs)
        self.setLayout(self.layout)
