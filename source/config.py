# -*- coding: utf-8 -*-
# !/usr/bin/env python3

# Copyright (c) 2021 Filippenok Dmitriy <filippenok@gmail.com>
# Date: 15.06.2021
# Time: 0:06
from typing import Optional

import os
from configparser import ConfigParser

import logging

from sys_libs.directories import checkFilePath

log = logging.getLogger('main')


class ExtendedConfigParser(ConfigParser):
    def __init__(self, filename, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._filename = filename
        checkFilePath(self._filename)

        self.read(self._filename, encoding='utf-8')

        self._isNeedSave = False

    def isExists(self, section, name, default_value):
        if f"{section}" not in self:
            self[f"{section}"] = {}
            # self._isNeedSave = True
        if f"{name}" not in self[f"{section}"]:
            self[f"{section}"][f"{name}"] = f'{default_value}'
            self._isNeedSave = True

    def set(self, section: str, option: str, value: Optional[str] = ...) -> None:
        self._isNeedSave = True
        super().set(section, option, value)

    def save(self):
        if self._isNeedSave:
            with open(f"{self._filename}.tmp", 'w', encoding='utf-8') as configfile:
                self.write(configfile)
                self._isNeedSave = False
            try:
                self.read(f"{self._filename}.tmp", encoding='utf-8')
            except Exception as err:
                log.error(f"Ошибка записи файла настроек: {err}")
                return False
            else:
                try:
                    os.replace(self._filename, f"{self._filename}.bak")
                except OSError as err:
                    log.error(f"Невозможно заменить файл настроек: {err}")
                else:
                    log.debug(f"config file {self._filename} переименован в {self._filename}.bak")
                try:
                    os.replace(f"{self._filename}.tmp", self._filename)
                except OSError as err:
                    log.error(f"Невозможно заменить файл настроек: {err}")
                    return False
                else:
                    log.debug(f"config file {self._filename} сохранён")
        return True

