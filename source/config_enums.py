# -*- coding: utf-8 -*-
# !/usr/bin/env python3

# Copyright (c) 2021 Filippenok Dmitriy <filippenok@gmail.com>
# Date: 09.03.2021
# Time: 10:59

from enum import Enum


class SettingsHeaders(Enum):
    System = 'system'
    Scanners = 'scanners'
    Db = 'db_settings'
    Serializer = 'serializer'
    Printer = 'printer'
    Camera = 'camera'
    Mcdn = 'mcdn'

    def __str__(self):
        return self.value


class SettingsValues(Enum):
    SystemScanners = 'scanners_quantity'
    SystemLineNumber = 'line_number'
    SystemEnableItemPerBox = 'enable_items_per_box'
    SystemFontSize = 'font_size'
    SystemLinesQuantity = 'lines_quantity'
    SystemShowDocDialog = 'show_doc_dialog'
    SystemCheckRollEnabled = 'check_roll_mode_enabled'
    SystemPrintingEnabled = 'printing_enabled'
    SystemCameraEnabled = 'camera_enabled'
    SystemApplicatorMode = 'applicator_mode'
    SystemPlcSettingsMode = 'plc_settings_mode'
    SystemFixedReceiveWindow = 'fixed_receive_window'
    SystemReceiveWindowWidth = 'receive_window_width'

    ScannerBaudRate = 'scanner_baud'
    ScannerPort = 'scanner_port'
    ScannerSubtraction = 'scanner_subtraction'

    DbHost = 'postgresql_db_host'
    DbPort = 'postgresql_db_port'
    DbName = 'postgresql_db_name'
    DbUser = 'postgresql_db_user'
    DbPass = 'postgresql_db_password'
    DbAdmin = 'postgresql_db_admin'
    DbAdminPass = 'postgresql_db_admin_password'

    SerialSplit = 'split_report_by_gtin'
    SerialJobDepended = 'split_job_depended'
    SerialPath = 'path_for_xml_export'
    SerialOrgName = 'org_name'
    SerialInn = 'inn'
    SerialKpp = 'kpp'
    SerialCountry = 'country_code'
    SerialAddress = 'text_address'
    SerialPhone = 'phone_number'
    SerialEmail = 'email'

    CameraIpAddress = 'camera_ip'
    CameraPort = 'camera_port'

    PrinterProtocol = 'printer_protocol'
    PrinterTildaMode = 'tilda_mode'
    PrinterConnection = 'printer_connection_type'
    PrinterIpAddress = 'printer_ip'
    PrinterPort = 'printer_port'
    PrinterName = 'printer_name'
    PrinterDesignName = 'design_name'
    PrinterVarName = 'var_name'

    McdnServer = 'server'
    McdnClientToken = 'client_token'
    McdnOwnerId = 'owner_id'
    McdnFilePath = 'path'

    def __str__(self):
        return self.value
