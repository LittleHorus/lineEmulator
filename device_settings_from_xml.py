#!/usr/bin/python3
# -*- coding: utf-8 -*-

import numpy as np
import os
import sys
import traceback
import struct
import xml.etree.ElementTree as ET


__version__ = '1.0.0.a'


class XmlDataLoader():
	def __init__(self, parent = None):
		
		self.device_dict = dict()
		header = list()

	def xml_load(self, path):
		try:
			tree = ET.parse(path)
			root = tree.getroot()
			device_type = 0
			device_protocol_version = 0
			device_address = 0
			for i in range(len(list(root[0]))):
				if root[0][i].tag == 'alias':
					device_type = root[0][i].text
				if root[0][i].tag == 'version':
					device_protocol_version = root[0][i].text
				if root[0][i].tag == 'address':
					device_address = int(root[0][i].text, 16)
			self.device_dict.update({"device":device_type, "version": device_protocol_version, "address": device_address})
			self.device_dict.update({'elements':{'regs':0}})

			for i in range(len(list(root[1]))):
				att_alias = root[1][i].attrib['alias']
					
				for j in range(len(list(root[1][i]))):
					if root[1][i][j].tag == 'address':
						addr = root[1][i][j].text
					if root[1][i][j].tag == 'caption':
						caption = root[1][i][j].text	
					if root[1][i][j].tag == 'rw':
						rw = root[1][i][j].text					
					if root[1][i][j].tag == 'description':
						desc = root[1][i][j].text
					if root[1][i][j].tag == 'type':
						type_ = root[1][i][j].text
					if root[1][i][j].tag == 'default_view':
						def_view = root[1][i][j].text		
					if root[1][i][j].tag == 'data_presentation':
						data_pres = root[1][i][j].text	
						#if root[1][i][j]

				
				self.device_dict['elements'].update({addr:{'alias':att_alias,\
				 'caption':caption, 'rw': rw, 'description': desc, 'type': type_,\
				  'default_view':def_view, 'data_presentation':data_pres}})
				self.device_dict['elements']['regs'] += 1
			print(self.device_dict)									
		except:
			traceback.print_exc()


class data_flex():
	def __init__(self):
		self.data_dict = {'packet_count': 0, 'regs': {0: 0}}

	def incoming_data(self, data, reg):
		if reg in self.data_dict['regs']:
			self.data_dict['regs'][reg] = data
		else:
			self.data_dict['regs'].update({reg:data})
'''
for i in range(len(list(root[1]))):
    print(root[1][i].tag, root[1][i].attrib)
    for j in range(len(list(root[1][i]))):
        if root[1][i][j].attrib != {}:
            print('\t',root[1][i][j].tag, root[1][i][j].attrib)
            for k in range(len(list(root[1][i][j]))):
                if root[1][i][j][k].attrib == {}:
                    print('\t\t',root[1][i][j][k].tag, root[1][i][j][k].text)
                else:
                    print('\t\t',root[1][i][j][k].tag, root[1][i][j][k].attrib)
                    for n in range(len(list(root[1][i][j][k]))):
                        print('\t\t\t',root[1][i][j][k][n].tag, root[1][i][j][k][n].text) 
        else:
            print('\t',root[1][i][j].tag, root[1][i][j].text) 
    print('\n')'''