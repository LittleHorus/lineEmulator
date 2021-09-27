# -*- coding: utf-8 -*-
# !/usr/bin/env python3

# Copyright (c) 2020 Filippenok Dmitriy <filippenok@gmail.com>
# Date: 07.10.2020
# Time: 12:15

import logging
import struct
from enum import IntEnum, Enum, auto

from sys_libs.common_functions import convertType

log = logging.getLogger('main')

SOURCE_ID = 0x01


class ParsingDataStates(Enum):
    Non = auto()
    Init = auto()
    WaitingLength = auto()
    WaitingData = auto()
    Complete = auto()


class DataTypeEnum(IntEnum):
    Unknown = 0
    uint8 = 0x01
    int8 = 0x01
    uint16 = 0x02
    int16 = 0x02
    uint32 = 0x03
    int32 = 0x03
    float = 0x04
    real = 0x04
    array = 0x05
    string = 0x05

    def _missing_(self, value):
        return self.Unknown


class CommandEnum(IntEnum):
    Unknown = 0
    Write = 0x10
    Read = 0x20
    Error = 0x50
    Response = 0x60
    Notify = 0x70

    def _missing_(self, value):
        return self.Unknown


unpacking_formats = {
    DataTypeEnum.array: 'B ',
    DataTypeEnum.string: 's',
    DataTypeEnum.uint8: 'B',
    DataTypeEnum.int8: 'b',
    DataTypeEnum.uint16: 'H',
    DataTypeEnum.int16: 'h',
    DataTypeEnum.uint32: 'L',
    DataTypeEnum.int32: 'l',
    DataTypeEnum.float: 'f',
    DataTypeEnum.real: 'f',
}

unpack_direction: str = '>'


class DataPacket:
    def __init__(self, *args, source_id=SOURCE_ID, target_id=0x02, element_id=0, data=None, **kwargs):
        super().__init__(*args, **kwargs)

        self._parsingState = ParsingDataStates.Init

        self._sourceId = source_id
        self._targetId = target_id
        self._command = CommandEnum.Read
        self._dataType = DataTypeEnum.uint32

        self._elementId = element_id
        self._packedData = b''
        # self.data = 0
        self._dataLength = 4

        self._bytesToRead = 5
        self._offset = 0

        if data is not None:
            self.unpackInitPart(data)

    @property
    def source(self):
        return self._sourceId

    @property
    def target(self):
        return self._targetId

    @property
    def element_id(self):
        return self._elementId

    @element_id.setter
    def element_id(self, value):
        self._elementId = convertType(value, int, 0)

    @property
    def data(self):
        if self._dataType is not DataTypeEnum.array:
            try:
                fmt = f"{unpacking_formats[self._dataType]}"  # if self._dataType is not DataTypeEnum.Array else f"{len(self._packedData)}{unpacking_formats[self._dataType]}"
                data, = struct.unpack(unpack_direction+fmt, self._packedData)
            except (struct.error, KeyError) as err:
                log.error(f"{err}: {self.element_id} {self._packedData.hex()}")
                raise ValueError
        else:
            data = self._packedData.decode('utf-8')
        return data

    @data.setter
    def data(self, value):
        # todo добавить обработку записи данных для длинного пакета переменной длины
        try:
            if 's' in unpacking_formats[self._dataType]:
                value = b''
            self._packedData = struct.pack(unpack_direction+unpacking_formats[self._dataType], value)
        except struct.error as err:
            log.debug(f"{err}. {value} (element id {self.element_id})")

    @property
    def packed_data(self):
        return self._packedData

    @packed_data.setter
    def packed_data(self, value):
        self._packedData = value

    @property
    def command(self) -> CommandEnum:
        return self._command

    @command.setter
    def command(self, value):
        self._command = value

    @property
    def data_type(self) -> DataTypeEnum:
        return self._dataType
    
    @data_type.setter
    def data_type(self, value: DataTypeEnum):
        self._dataType = value
        if self._dataType is DataTypeEnum.array:
            self._dataLength = 0
        elif self._dataType in (DataTypeEnum.uint8, DataTypeEnum.int8):
            self._dataLength = 1
        elif self._dataType in (DataTypeEnum.uint16, DataTypeEnum.int16):
            self._dataLength = 2
        elif self._dataType in (DataTypeEnum.uint32, DataTypeEnum.int32, DataTypeEnum.float):
            self._dataLength = 4

    @property
    def data_length(self):
        return self._dataLength

    def unpackData(self, unpacking_format, offset=0, length=4):
        # log.debug(f'{unpacking_format}, {offset}, {length}')
        try:
            # log.debug(struct.unpack(unpacking_format, self._packedData[offset:offset+length]))
            return struct.unpack(unpacking_format, self._packedData[offset:offset+length])
        except struct.error:
            return tuple()

    def packData(self, packing_format, *args):
        self._packedData = struct.pack(packing_format, *args)

    def unpackInitPart(self, data):
        self._sourceId, self._targetId, cmd, self._elementId = struct.unpack(f'{unpack_direction}BBBH', data[:5])

        self._command = CommandEnum(cmd & 0xF0)
        self.data_type = DataTypeEnum(cmd & 0x0F)
        self._parsingState = ParsingDataStates.WaitingData
        if self._dataType is DataTypeEnum.array:
            self._dataLength = 0
            self._parsingState = ParsingDataStates.WaitingLength
        # if self._dataType is DataTypeEnum.UInt8:
        #     self._dataLength = 1
        # elif self._dataType is DataTypeEnum.UInt16:
        #     self._dataLength = 2
        # elif self._dataType is DataTypeEnum.UInt32 or self._dataType is DataTypeEnum.Float:
        #     self._dataLength = 4
        self._bytesToRead = self._dataLength
        if self._bytesToRead == 0:
            self._bytesToRead = 4

    def parseData(self, data):
        # log.debug(f"Received: {struct.unpack('<'+'B'*len(data), data)} {len(data)}bytes")
        if self._parsingState is ParsingDataStates.Init:
            self.unpackInitPart(data)
        elif self._parsingState is ParsingDataStates.WaitingLength:
            if self._dataType is DataTypeEnum.array:
                if self._dataLength == 0:
                    self._dataLength, = struct.unpack(unpack_direction+'L', data[:4])
                    log.debug(self._dataLength)
                    self._bytesToRead = self._dataLength
                    self._parsingState = ParsingDataStates.WaitingData
                    # return
        elif self._parsingState is ParsingDataStates.WaitingData:
            # log.debug(data)
            self._packedData = data[:self._dataLength]
            self._bytesToRead = 0
            self._parsingState = ParsingDataStates.Complete

    # def isFilled(self):
    #     return len(self._packedData) == self._dataLength

    @property
    def bytes_to_read(self):
        return self._bytesToRead

    @property
    def as_bytes(self):
        # log.debug(self._sourceId, self._targetId, self._command.value|self._dataType.value, self._elementId)
        header = struct.pack(unpack_direction+'BBBH', self._sourceId, self._targetId, self._command.value|self._dataType.value, self._elementId)
        if self._dataType is DataTypeEnum.array:
            header += struct.pack(unpack_direction+'L', self._dataLength)
        return header + self._packedData

    def __str__(self):
        string = f"{self._dataLength} {self._sourceId:02X} {self._targetId:02X} {self._command.value|self._dataType.value:02X} {self._elementId:04X}"
        if self._dataType is DataTypeEnum.array:
            string += f" {self._dataLength:08X}"
            for bt in self.unpackData(unpack_direction + 'B'*self._dataLength, offset=0, length=self._dataLength):
                string += f" {bt:02X}"
            # string += f" ({self._packedData.decode('utf-8')})"
            try:
                string += f' ({self.data})'
            except ValueError as error:
                log.error(f"{error}: {self._packedData}")

        elif self._dataType is DataTypeEnum.float:
            string += ' '
            for bt in self.unpackData(unpack_direction + 'B'*self._dataLength):
                string += f"{bt:02X}"
            try:
                string += f' ({self.data})'
            except ValueError as error:
                log.error(f"{error}: {self._packedData}")

        else:
            try:
                string += ' {:0{width}X}'.format(self.data, width=self._dataLength*2)
            except ValueError as error:
                log.error(f"{error}: {self._packedData}")
            try:
                string += f' ({self.data})'
            except ValueError as error:
                log.error(f"{error}: {self._packedData}")

        return string

    def __repr__(self):
        return self.__str__()

