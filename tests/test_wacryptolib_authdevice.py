# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

from datetime import datetime
from pathlib import Path

from wacryptolib.authdevice import list_available_authdevices, _find_authdevices_in_macosx_system_profiler_data


def test_list_available_authdevices():  # FIXME add mockups to simulate real USB key?
    authdevices_list = list_available_authdevices()
    assert isinstance(authdevices_list, list)

    for authdevice in authdevices_list:  # Only works if REAL USB KEY is plugged!
        print(">> USB key detected:", authdevice)

        assert len(authdevice) == 6  # Same format on all platforms

        assert isinstance(authdevice, dict)

        assert isinstance(authdevice["device_type"], str)
        assert authdevice["device_type"] == "USBSTOR"

        assert isinstance(authdevice["partition_mountpoint"], str)
        assert Path(authdevice["partition_mountpoint"]).exists()

        assert isinstance(authdevice["partition_label"], str)  # Might be empty

        assert isinstance(authdevice["filesystem_format"], str)
        assert authdevice["filesystem_format"]

        assert isinstance(authdevice["filesystem_size"], int)
        assert authdevice["filesystem_size"] > 0

        assert Path(authdevice["authenticator_dir"]).parent == Path(authdevice["partition_mountpoint"])


def test_find_authdevices_in_macosx_system_profiler_data():
    plist_output = [
        {
            "_SPCommandLineArguments": [
                "/usr/sbin/system_profiler",
                "-nospawn",
                "-xml",
                "SPUSBDataType",
                "-detailLevel",
                "full",
            ],
            "_SPCompletionInterval": 0.07972097396850586,
            "_SPResponseTime": 0.1565159559249878,
            "_dataType": "SPUSBDataType",
            "_detailLevel": -1,
            "_items": [
                {"_name": "USB31Bus", "host_controller": "AppleT8103USBXHCI"},
                {
                    "_items": [
                        {
                            "Media": [
                                {
                                    "Logical Unit": 0,
                                    "USB Interface": 0,
                                    "_name": "Voyager",
                                    "bsd_name": "disk4",
                                    "partition_map_type": "master_boot_record_partition_map_type",
                                    "removable_media": "yes",
                                    "size": "15,51 GB",
                                    "size_in_bytes": 15513354240,
                                    "smart_status": "Verified",
                                    "volumes": [
                                        {
                                            "_name": "Install macOS " "Monterey",
                                            "bsd_name": "disk4s1",
                                            "file_system": "Journaled " "HFS+",
                                            "free_space": "2,06 GB",
                                            "free_space_in_bytes": 2058493952,
                                            "iocontent": "Apple_HFS",
                                            "mount_point": "/Volumes/Install " "macOS " "Monterey",
                                            "size": "15,51 GB",
                                            "size_in_bytes": 15511584768,
                                            "volume_uuid": "B7F7646A-3185-3870-8CBE-6929034CCBD6",
                                            "writable": "yes",
                                        }
                                    ],
                                }
                            ],
                            "_name": "Voyager",
                            "bcd_device": "1.00",
                            "bus_power": "500",
                            "bus_power_used": "200",
                            "device_speed": "high_speed",
                            "extra_current_used": "0",
                            "location_id": "0x00100000 / 1",
                            "manufacturer": "Corsair",
                            "product_id": "0x1ab1",
                            "serial_num": "07085378AC1C1696",
                            "vendor_id": "0x1b1c  (CORSAIR MEMORY INC.)",
                        }
                    ],
                    "_name": "USB31Bus",
                    "host_controller": "AppleT8103USBXHCI",
                },
                {
                    "_items": [
                        {
                            "_name": "USB3.0 Hub             ",
                            "bcd_device": "b.e1",
                            "bus_power": "900",
                            "bus_power_used": "0",
                            "device_speed": "super_speed",
                            "extra_current_used": "0",
                            "location_id": "0x02600000 / 1",
                            "manufacturer": "VIA Labs, Inc.         ",
                            "product_id": "0x0812",
                            "vendor_id": "0x2109  (VIA Labs, Inc.)",
                        },
                        {
                            "_items": [
                                {
                                    "_name": "USB Keyboard",
                                    "bcd_device": "1.65",
                                    "bus_power": "500",
                                    "bus_power_used": "100",
                                    "device_speed": "low_speed",
                                    "extra_current_used": "0",
                                    "location_id": "0x02240000 / 4",
                                    "manufacturer": "Chicony",
                                    "product_id": "0x0402",
                                    "vendor_id": "0x04f2  (Chicony " "Electronics Co., Ltd.)",
                                },
                                {
                                    "_name": "Basic Optical Mouse",
                                    "bcd_device": "0.00",
                                    "bus_power": "500",
                                    "bus_power_used": "100",
                                    "device_speed": "low_speed",
                                    "extra_current_used": "0",
                                    "location_id": "0x02230000 / 5",
                                    "manufacturer": "Microsoft",
                                    "product_id": "0x0084",
                                    "vendor_id": "0x045e  (Microsoft " "Corporation)",
                                },
                            ],
                            "_name": "USB2.0 Hub             ",
                            "bcd_device": "b.e0",
                            "bus_power": "500",
                            "bus_power_used": "0",
                            "device_speed": "high_speed",
                            "extra_current_used": "0",
                            "location_id": "0x02200000 / 3",
                            "manufacturer": "VIA Labs, Inc.         ",
                            "product_id": "0x2812",
                            "vendor_id": "0x2109  (VIA Labs, Inc.)",
                        },
                        {
                            "Media": [
                                {
                                    "Logical Unit": 0,
                                    "USB Interface": 0,
                                    "_name": "SATAWire",
                                    "bsd_name": "disk6",
                                    "partition_map_type": "guid_partition_map_type",
                                    "removable_media": "no",
                                    "size": "480,1 GB",
                                    "size_in_bytes": 480103981056,
                                    "smart_status": "Verified",
                                    "volumes": [
                                        {
                                            "_name": "disk6s1",
                                            "bsd_name": "disk6s1",
                                            "iocontent": "Microsoft " "Reserved",
                                            "size": "16,8 MB",
                                            "size_in_bytes": 16759808,
                                        },
                                        {
                                            "_name": "disk6s2",
                                            "bsd_name": "disk6s2",
                                            "iocontent": "Apple_APFS",
                                            "size": "480,09 GB",
                                            "size_in_bytes": 480085278720,
                                        },
                                    ],
                                }
                            ],
                            "_name": "SATAWire        ",
                            "bcd_device": "1.08",
                            "bus_power": "500",
                            "bus_power_used": "2",
                            "device_speed": "high_speed",
                            "extra_current_used": "0",
                            "location_id": "0x02100000 / 2",
                            "manufacturer": "Apricorn",
                            "product_id": "0x0040",
                            "serial_num": "323230354536303537393230",
                            "vendor_id": "0x0984  (Apricorn)",
                        },
                    ],
                    "_name": "USB30Bus",
                    "host_controller": "AppleEmbeddedUSBXHCIFL1100",
                    "pci_device": "0x1100 ",
                    "pci_revision": "0x0010 ",
                    "pci_vendor": "0x1b73 ",
                },
            ],
            "_parentDataType": "SPHardwareDataType",
            "_properties": {
                "1284DeviceID": {"_order": "13"},
                "_name": {"_isColumn": "YES", "_isOutlineColumn": "YES", "_order": "0"},
                "bcd_device": {"_order": "3", "_suppressLocalization": "YES"},
                "bsd_name": {"_order": "42"},
                "bus_power": {"_order": "8"},
                "bus_power_desired": {"_order": "9"},
                "bus_power_used": {"_order": "10"},
                "detachable_drive": {"_order": "39"},
                "device_manufacturer": {"_order": "20"},
                "device_model": {"_order": "22"},
                "device_revision": {"_order": "24"},
                "device_serial": {"_order": "26"},
                "device_speed": {"_order": "5"},
                "disc_burning": {"_order": "32"},
                "extra_current_used": {"_order": "11"},
                "file_system": {"_order": "40"},
                "free_space": {"_deprecated": True, "_order": "19"},
                "free_space_in_bytes": {"_isByteSize": True, "_order": "19"},
                "location_id": {"_order": "7"},
                "manufacturer": {"_order": "6"},
                "mount_point": {"_order": "44"},
                "optical_drive_type": {"_order": "30"},
                "optical_media_type": {"_order": "31"},
                "product_id": {"_order": "1"},
                "removable_media": {"_order": "34"},
                "serial_num": {"_order": "4", "_suppressLocalization": "YES"},
                "size": {"_deprecated": True, "_order": "18"},
                "size_in_bytes": {"_isByteSize": True, "_order": "18"},
                "sleep_current": {"_order": "12"},
                "vendor_id": {"_order": "2"},
                "volumes": {"_detailLevel": "0"},
                "writable": {"_order": "36"},
            },
            "_timeStamp": datetime(2022, 5, 10, 11, 47, 19),
            "_versionInfo": {"com.apple.SystemProfiler.SPUSBReporter": "900.4.2"},
        }
    ]

    authdevices = _find_authdevices_in_macosx_system_profiler_data(plist_output)

    assert authdevices == [
        {
            "device_type": "USBSTOR",
            "filesystem_format": "Journaled HFS+",
            "filesystem_size": 15511584768,
            "partition_label": "Install macOS Monterey",
            "partition_mountpoint": "/Volumes/Install macOS Monterey",
        }
    ]
