import binascii
import copy
import decimal
import importlib.util
import math
import os
import random
import sys
import types
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from json import dumps as original_dumps
from json import loads as original_loads
from pprint import pprint
from typing import Any, Tuple, Type

import pytest
import pytz

sys.path.append(os.path.dirname(__file__))

import extjson
from extjson import (
    convert_from_extjson,
    convert_to_extjson,
    dump_to_json_bytes,
    dump_to_json_file,
    dump_to_json_str,
    dumps,
    extjson_decoder_object_hook,
    load_from_json_bytes,
    load_from_json_file,
    load_from_json_str,
    loads,
)


def _random_bool():
    return bool(random.getrandbits(1))


EXAMPLE_NATIVE_DATA_TREE = {
    "my_none": None,
    "my_bools": {"OK": True, "KO": False},
    "my_strs": ["", "abc", "hêll@\nällz"],
    "my_nans": [math.nan, Decimal("NaN")],
    "my_ints": [-197282632562525242626256252625, -11, 0, 27627262727, 273262853882627266372772373772646252624542543],
    "my_floats": [
        -math.inf,
        -138262872.27267262123456,
        -20.001,
        -17.0,
        -0.0,
        0.0,
        2.0,
        411.1234567890000002,
        2276372572.15,
        math.inf,
    ],
    "my_decimals": [
        Decimal("-Infinity"),
        Decimal("-138262872.272672622927825262262426245242524"),
        Decimal("-22.001"),
        Decimal("-3.0"),
        Decimal("-0.0"),
        Decimal("0.0"),
        Decimal("4.0"),
        Decimal("282872.2"),
        Decimal("2276372572.152926382527252762522265262"),
        Decimal("Infinity"),
    ],
    "my_dates": [
        datetime(1, 1, 1, tzinfo=pytz.utc),
        datetime(2025, 10, 22, 2, 3, 4, 543000, tzinfo=pytz.timezone("Pacific/Johnston")),
    ],
    "my_uids": [uuid.UUID("29b91799-7249-4266-a853-80123d7fd684"), uuid.UUID("29b91799-7249-4266-a853-80123d7fd684")],
    "my_bytes": [b"", b"hello world", b"\x00\x01\x02\x03\x04\x05\xfa\xfb\xfc\xfd\xfe\xff"],
}

EXAMPLE_EXTJSON_DATA_TREE_CANONICAL = {
    "my_bools": {"KO": False, "OK": True},
    "my_bytes": [
        {"$binary": {"base64": "", "subType": "00"}},
        {"$binary": {"base64": "aGVsbG8gd29ybGQ=", "subType": "00"}},
        {"$binary": {"base64": "AAECAwQF+vv8/f7/", "subType": "00"}},
    ],
    "my_dates": [{"$date": {"$numberLong": "-62135596800000"}}, {"$date": {"$numberLong": "1761136444543"}}],
    "my_nans": [{"$numberDouble": "NaN"}, {"$numberDecimal": "NaN"}],  # Never equal to anything
    "my_floats": [
        {"$numberDouble": "-Infinity"},
        {"$numberDouble": "-138262872.27267262"},  # TRUNCATED by Python
        {"$numberDouble": "-20.001"},
        {"$numberDouble": "-17.0"},
        {"$numberDouble": "-0.0"},
        {"$numberDouble": "0.0"},
        {"$numberDouble": "2.0"},
        {"$numberDouble": "411.123456789"},
        {"$numberDouble": "2276372572.15"},  # TRUNCATED by Python
        {"$numberDouble": "Infinity"},
    ],
    "my_decimals": [
        {
            "$numberDecimal": "-Infinity",
        },
        {
            "$numberDecimal": "-138262872.272672622927825262262426245242524",
        },
        {
            "$numberDecimal": "-22.001",
        },
        {
            "$numberDecimal": "-3.0",
        },
        {
            "$numberDecimal": "-0.0",
        },
        {
            "$numberDecimal": "0.0",
        },
        {
            "$numberDecimal": "4.0",
        },
        {
            "$numberDecimal": "282872.2",
        },
        {
            "$numberDecimal": "2276372572.152926382527252762522265262",
        },
        {
            "$numberDecimal": "Infinity",
        },
    ],
    "my_ints": [
        {"$numberLong": "-197282632562525242626256252625"},
        {"$numberInt": "-11"},
        {"$numberInt": "0"},
        {"$numberLong": "27627262727"},
        {"$numberLong": "273262853882627266372772373772646252624542543"},
    ],
    "my_none": None,
    "my_strs": ["", "abc", "hêll@\nällz"],
    "my_uids": [
        {"$binary": {"base64": "KbkXmXJJQmaoU4ASPX/WhA==", "subType": "04"}},
        {"$binary": {"base64": "KbkXmXJJQmaoU4ASPX/WhA==", "subType": "04"}},
    ],
}


EXAMPLE_EXTJSON_DATA_TREE_RELAXED = {
    "my_bools": {"KO": False, "OK": True},
    "my_bytes": [
        {"$binary": {"base64": "", "subType": "00"}},  # Always canonical for bytes
        {"$binary": {"base64": "aGVsbG8gd29ybGQ=", "subType": "00"}},
        {"$binary": {"base64": "AAECAwQF+vv8/f7/", "subType": "00"}},
    ],
    "my_dates": [{"$date": "0001-01-01T00:00:00Z"}, {"$date": "2025-10-22T02:03:04.543-10:31"}],
    "my_decimals": [
        {"$numberDecimal": "-Infinity"},
        {"$numberDecimal": "-138262872.272672622927825262262426245242524"},
        {"$numberDecimal": "-22.001"},
        {"$numberDecimal": "-3.0"},
        {"$numberDecimal": "-0.0"},
        {"$numberDecimal": "0.0"},
        {"$numberDecimal": "4.0"},
        {"$numberDecimal": "282872.2"},
        {"$numberDecimal": "2276372572.152926382527252762522265262"},
        {"$numberDecimal": "Infinity"},
    ],
    "my_floats": [
        {"$numberDouble": "-Infinity"},
        -138262872.27267262,
        -20.001,
        -17.0,
        -0.0,
        0.0,
        2.0,
        411.123456789,
        2276372572.15,
        {"$numberDouble": "Infinity"},
    ],
    "my_ints": [-197282632562525242626256252625, -11, 0, 27627262727, 273262853882627266372772373772646252624542543],
    "my_nans": [{"$numberDouble": "NaN"}, {"$numberDecimal": "NaN"}],  # Never equal to anything
    "my_none": None,
    "my_strs": ["", "abc", "hêll@\nällz"],
    "my_uids": [{"$uuid": "29b9179972494266a85380123d7fd684"}, {"$uuid": "29b9179972494266a85380123d7fd684"}],
}


def test_extended_json_tree_encode_decode_in_canonical_mode():

    example_native_data_tree = copy.deepcopy(EXAMPLE_NATIVE_DATA_TREE)

    ext_json = convert_to_extjson(example_native_data_tree, canonical=True)
    print("EXTJSON DUMP CANONICAL:")
    pprint(ext_json)

    expected_ext_json = EXAMPLE_EXTJSON_DATA_TREE_CANONICAL
    assert ext_json == expected_ext_json

    decoded_native_data_tree = convert_from_extjson(ext_json)
    print("DECODED NATIVE DUMP:")
    pprint(decoded_native_data_tree)

    assert decoded_native_data_tree != example_native_data_tree  # Some little incompatibilities exist
    assert all(math.isnan(x) for x in decoded_native_data_tree["my_nans"])
    del decoded_native_data_tree["my_nans"]
    del example_native_data_tree["my_nans"]

    assert decoded_native_data_tree == {
        "my_bools": {"KO": False, "OK": True},
        "my_bytes": [b"", b"hello world", b"\x00\x01\x02\x03\x04\x05\xfa\xfb\xfc\xfd\xfe\xff"],
        "my_dates": [
            datetime(1, 1, 1, 0, 0, tzinfo=pytz.utc),
            datetime(2025, 10, 22, 12, 34, 4, 543000, tzinfo=pytz.utc),
        ],  # Timezone was changed!
        "my_ints": [
            -197282632562525242626256252625,
            -11,
            0,
            27627262727,
            273262853882627266372772373772646252624542543,
        ],
        "my_floats": [
            -math.inf,
            -138262872.27267262,
            -20.001,
            -17.0,
            -0.0,
            0.0,
            2.0,
            411.123456789,
            2276372572.15,
            math.inf,
        ],
        "my_decimals": [
            Decimal("-Infinity"),
            Decimal("-138262872.272672622927825262262426245242524"),
            Decimal("-22.001"),
            Decimal("-3.0"),
            Decimal("-0.0"),
            Decimal("0.0"),
            Decimal("4.0"),
            Decimal("282872.2"),
            Decimal("2276372572.152926382527252762522265262"),
            Decimal("Infinity"),
        ],
        "my_none": None,
        "my_strs": ["", "abc", "hêll@\nällz"],
        "my_uids": [
            uuid.UUID("29b91799-7249-4266-a853-80123d7fd684"),
            uuid.UUID("29b91799-7249-4266-a853-80123d7fd684"),
        ],
    }

    assert decoded_native_data_tree == example_native_data_tree  # ROUND-TRIP EQUALITY AFTER REMOVING NaN


def test_extended_json_tree_encode_decode_in_relaxed_mode():

    example_native_data_tree = copy.deepcopy(EXAMPLE_NATIVE_DATA_TREE)

    ext_json = convert_to_extjson(example_native_data_tree, canonical=False)
    print("EXTJSON DUMP RELAXED:")
    pprint(ext_json)

    expected_ext_json = EXAMPLE_EXTJSON_DATA_TREE_RELAXED
    assert ext_json == expected_ext_json

    decoded_native_data_tree = convert_from_extjson(ext_json)
    print("DECODED NATIVE DUMP:")
    pprint(decoded_native_data_tree)

    assert decoded_native_data_tree != example_native_data_tree  # Some little incompatibilities exist
    assert all(math.isnan(x) for x in decoded_native_data_tree["my_nans"])

    del decoded_native_data_tree["my_nans"]
    del example_native_data_tree["my_nans"]

    assert decoded_native_data_tree == {
        "my_bools": {
            "KO": False,
            "OK": True,
        },
        "my_bytes": [
            b"",
            b"hello world",
            b"\x00\x01\x02\x03\x04\x05\xfa\xfb\xfc\xfd\xfe\xff",
        ],
        "my_dates": [
            datetime(1, 1, 1, 0, 0, tzinfo=pytz.utc),
            datetime(2025, 10, 22, 12, 34, 4, 543000, tzinfo=pytz.utc),
        ],  # Equivalent
        "my_decimals": [
            Decimal("-Infinity"),
            Decimal("-138262872.272672622927825262262426245242524"),
            Decimal("-22.001"),
            Decimal("-3.0"),
            Decimal("-0.0"),
            Decimal("0.0"),
            Decimal("4.0"),
            Decimal("282872.2"),
            Decimal("2276372572.152926382527252762522265262"),
            Decimal("Infinity"),
        ],
        "my_floats": [
            -math.inf,
            -138262872.27267262,
            -20.001,
            -17.0,
            -0.0,
            0.0,
            2.0,
            411.123456789,
            2276372572.15,
            math.inf,
        ],
        "my_ints": [
            -197282632562525242626256252625,
            -11,
            0,
            27627262727,
            273262853882627266372772373772646252624542543,
        ],
        "my_none": None,
        "my_strs": [
            "",
            "abc",
            "hêll@\nällz",
        ],
        "my_uids": [
            uuid.UUID("29b91799-7249-4266-a853-80123d7fd684"),
            uuid.UUID("29b91799-7249-4266-a853-80123d7fd684"),
        ],
    }

    assert decoded_native_data_tree == example_native_data_tree  # ROUND-TRIP EQUALITY AFTER REMOVING NaN


def test_extended_json_primitive_encode_decode_in_all_modes():

    operations = 0

    def _test_primitive_encode_decode(_item, canonical):
        nonlocal operations
        operations += 1
        ext_json = convert_to_extjson(_item, canonical=canonical)
        decoded_item = convert_from_extjson(ext_json)
        if isinstance(_item, (float, Decimal)) and math.isnan(_item):
            assert math.isnan(decoded_item)  # No equality between NaNs
        else:
            assert decoded_item == _item, (repr(_item), repr(decoded_item))

    for canonical_mode in [True, False]:
        for value in EXAMPLE_NATIVE_DATA_TREE.values():
            if isinstance(value, list):
                for item in value:
                    _test_primitive_encode_decode(item, canonical=canonical_mode)
            elif isinstance(value, dict):
                for item in value.values():
                    _test_primitive_encode_decode(item, canonical=canonical_mode)
            else:
                _test_primitive_encode_decode(value, canonical=canonical_mode)

    assert operations > 20, operations


def test_extended_json_subclass_encode_decode():

    test_cases: list[Tuple[Type, Any]] = [
        (int, (1,)),
        (int, (2 << 60,)),
        (float, (1.1,)),
        (decimal.Decimal, ("199.222",)),
        (str, ("str",)),
        (bytes, (b"bytes",)),
        (datetime, (2024, 1, 16, 0, 0, 0, 0, timezone.utc)),
        (uuid.UUID, ("f47ac10b-58cc-4372-a567-0e02b2c3d479",)),
    ]

    for cls, args in test_cases:
        basic_obj = cls(*args)
        my_cls = type(f"My{cls.__name__}", (cls,), {})
        my_obj = my_cls(*args)
        assert basic_obj == my_obj

        for canonical_mode in [True, False]:
            # Check equivalence of converted format
            basic_converted = convert_to_extjson(basic_obj, canonical=canonical_mode)
            subclass_converted = convert_to_extjson(my_obj, canonical=canonical_mode)
            assert basic_converted == subclass_converted

            # Check that subclass equality works fine here
            roundtrip_obj = convert_from_extjson(subclass_converted)
            assert roundtrip_obj == basic_obj
            assert roundtrip_obj == my_obj

    # Subclasses overriding their text representation must not alter the canonical output
    for cls, value in [(int, 1), (int, 2 << 60), (float, 1.5)]:
        overrides = {"__repr__": lambda self: "custom", "__str__": lambda self: "custom"}
        my_obj = type(f"MyCustom{cls.__name__}", (cls,), overrides)(value)
        converted = convert_to_extjson(my_obj, canonical=True)
        assert converted == convert_to_extjson(value, canonical=True)
        assert convert_from_extjson(converted) == value


def test_extended_json_specific_cases():

    assert convert_from_extjson({"$undefined": True}) is None
    assert convert_from_extjson({"$undefined": False}) is None

    assert convert_from_extjson({"$unrecognized": 33}) == {"$unrecognized": 33}

    # Handle tuple objects as lists, since JSON does not have a tuple type
    _tuple_obj = (1, b"abc")
    _tuple_obj_extjson = convert_to_extjson(_tuple_obj)
    assert _tuple_obj_extjson == [1, {"$binary": {"base64": "YWJj", "subType": "00"}}]
    assert convert_from_extjson(_tuple_obj_extjson) == list(_tuple_obj)

    # If conversion is impossible, we just let the object as is
    input = {"unsupported": timedelta(days=3)}
    assert convert_to_extjson(input, canonical=True) == input
    assert convert_to_extjson(input, canonical=False) == input

    # Check that naive datetimes are rejected
    with pytest.raises(TypeError, match="naive"):
        convert_to_extjson(datetime(2024, 1, 16, 0, 0, 0, 0), canonical=_random_bool())

    # Check the handling of timezones in roundtrips
    utc_date = datetime(1876, 12, 18, microsecond=11000, tzinfo=pytz.utc)
    utc_date_2 = convert_from_extjson(convert_to_extjson(utc_date, canonical=_random_bool()))
    assert utc_date_2 == utc_date
    assert utc_date_2.tzinfo == timezone.utc

    other_date = datetime(2022, 2, 1, 22, 23, 34, 26000, tzinfo=pytz.timezone("Pacific/Johnston"))
    other_date_2 = convert_from_extjson(convert_to_extjson(other_date, canonical=True))
    assert other_date_2 == other_date
    assert other_date_2.tzinfo == timezone.utc  # CHANGED in canonical mode
    other_date_3 = convert_from_extjson(convert_to_extjson(other_date, canonical=False))
    assert other_date_3 == other_date
    # UNCHANGED in relaxed mode, but under a different timezone format:
    assert other_date_3.tzinfo == timezone(timedelta(days=-1, seconds=48540))

    # Only a zero offset becomes "Z", not offsets starting with "+00:00" but having seconds
    assert convert_to_extjson(datetime(2020, 1, 1, tzinfo=timezone.utc), canonical=False) == {
        "$date": "2020-01-01T00:00:00Z"
    }
    seconds_offset_date = datetime(2020, 1, 1, tzinfo=timezone(timedelta(seconds=30)))
    seconds_offset_extjson = convert_to_extjson(seconds_offset_date, canonical=False)
    assert seconds_offset_extjson == {"$date": "2020-01-01T00:00:00+00:00:30"}
    seconds_offset_date_2 = convert_from_extjson(seconds_offset_extjson)
    assert seconds_offset_date_2 == seconds_offset_date
    assert seconds_offset_date_2.utcoffset() == timedelta(seconds=30)

    # Check that microseconds are not entirely preserved in roundtrips
    for canonical_mode in [True, False]:
        # Negative timestamp compared to EPOCH
        precise_date = datetime(1876, 12, 18, microsecond=16843, tzinfo=pytz.utc)
        _extjson = convert_to_extjson(precise_date, canonical=canonical_mode)
        precise_date_2 = convert_from_extjson(_extjson)
        assert precise_date_2 != precise_date
        assert precise_date_2.microsecond == 16000  # Floored number

        # Positive timestamp compared to EPOCH
        precise_date = datetime(2024, 12, 18, microsecond=16343, tzinfo=pytz.utc)
        _extjson = convert_to_extjson(precise_date, canonical=canonical_mode)
        precise_date_2 = convert_from_extjson(_extjson)
        assert precise_date_2 != precise_date
        assert precise_date_2.microsecond == 16000  # Floored number


def test_decimal_special_values_round_trip():
    # Decimal has its own Infinity/-Infinity/NaN/-NaN, distinct from the float ones,
    # and $numberDecimal always uses the canonical (str()) representation in both modes.
    for canonical_mode in [True, False]:
        for value, expected_str in [
            (Decimal("Infinity"), "Infinity"),
            (Decimal("-Infinity"), "-Infinity"),
            (Decimal("NaN"), "NaN"),
            (Decimal("-NaN"), "-NaN"),
        ]:
            ext_json = convert_to_extjson(value, canonical=canonical_mode)
            assert ext_json == {"$numberDecimal": expected_str}

            decoded = convert_from_extjson(ext_json)
            assert isinstance(decoded, Decimal)
            if value.is_nan():
                assert decoded.is_nan()
                assert decoded.is_signed() == value.is_signed()  # NaN vs -NaN
            else:
                assert decoded.is_infinite()
                assert decoded == value  # Infinity/-Infinity compare equal to themselves


def test_extended_json_datetime_truncation_consistency_for_distant_years():
    # Float timestamps lack sub-millisecond precision for such years, so they must not be used
    for year in (1, 1876, 1970, 2024, 5000, 9999):
        for microsecond in (0, 1000, 123999, 999990, 999999):
            date = datetime(year, 12, 31, 23, 59, 59, microsecond, tzinfo=timezone.utc)
            expected = date.replace(microsecond=microsecond // 1000 * 1000)
            for canonical_mode in [True, False]:
                roundtrip_date = convert_from_extjson(convert_to_extjson(date, canonical=canonical_mode))
                assert roundtrip_date == expected, (canonical_mode, date, roundtrip_date)

    # Upper bound of Python datetimes must not overflow to year 10000
    max_date = datetime.max.replace(tzinfo=timezone.utc)
    assert convert_to_extjson(max_date, canonical=True) == {"$date": {"$numberLong": "253402300799999"}}


def test_extended_json_undecodable_payloads():

    # The presence of other keys blocks extjson decoding
    skipped_payloads = [
        {"$date": "something", "somekey": True},
        {"$binary": "something", "somekey": True},
        {"$uuid": "something", "somekey": True},
        {"$undefined": "something", "somekey": True},
        {"$numberInt": "something", "somekey": True},
        {"$numberLong": "something", "somekey": True},
        {"$numberDouble": "something", "somekey": True},
        {"$numberDecimal": "something", "somekey": True},
    ]
    for skipped_payload in skipped_payloads:
        assert convert_from_extjson(skipped_payload) == skipped_payload

    broken_payloads = [
        {"$date": 3.12},
        {"$date": True},  # Not mistaken for a millisecond int
        {"$date": False},
        {"$binary": 42},
        {"$binary": {"badkey": True}},
        {"$binary": {"base64": "736", "subType": "00", "badkey": True}},
        {
            "$binary": {
                "base64": 333,
                "subType": "00",
            }
        },
        {"$binary": {"base64": "736", "subType": "002"}},
        {"$binary": 42},
        {"$uuid": 343},
        {"$numberInt": 3343},
        {"$numberLong": 272727},
        {"$numberDouble": 1337.3},
        {"$numberDecimal": 10.0},
    ]
    for broken_payload in broken_payloads:
        with pytest.raises(TypeError, match="must be"):
            convert_from_extjson(broken_payload)

    # Ensure that subTypes of binary are handled properly
    with pytest.raises(TypeError, match="subtype"):
        convert_from_extjson(
            {
                "$binary": {
                    "base64": "QUI=",
                    "subType": "01",
                }
            },
        )

    # Single-digit subTypes are accepted too
    assert convert_from_extjson({"$binary": {"base64": "KbkXmXJJQmaoU4ASPX/WhA==", "subType": "4"}}) == uuid.UUID(
        "29b91799-7249-4266-a853-80123d7fd684"
    )

    # Well-typed but malformed values let the underlying parser errors propagate
    with pytest.raises(binascii.Error):
        convert_from_extjson({"$binary": {"base64": "QUI", "subType": "00"}})  # Bad padding
    with pytest.raises(ValueError, match="16"):
        convert_from_extjson({"$binary": {"base64": "QUI=", "subType": "04"}})  # Not 16 bytes
    with pytest.raises(ValueError, match="base 16"):
        convert_from_extjson({"$binary": {"base64": "QUI=", "subType": "zz"}})
    with pytest.raises(ValueError, match="UUID"):
        convert_from_extjson({"$uuid": "nope"})
    with pytest.raises(ValueError, match="base 10"):
        convert_from_extjson({"$numberInt": "1.5"})
    with pytest.raises(decimal.InvalidOperation):
        convert_from_extjson({"$numberDecimal": "abc"})
    with pytest.raises(OverflowError):
        convert_from_extjson({"$date": {"$numberLong": "99999999999999999999"}})


def test_extended_json_int32_int64_boundaries():
    int32_values = [-(2**31), -1, 0, 2**31 - 1]
    int64_values = [-(2**31) - 1, 2**31, 2**63 - 1, -(2**63)]

    for value in int32_values:
        assert convert_to_extjson(value, canonical=True) == {"$numberInt": str(value)}
    for value in int64_values:
        assert convert_to_extjson(value, canonical=True) == {"$numberLong": str(value)}

    for value in int32_values + int64_values:
        assert convert_to_extjson(value, canonical=False) == value  # Never wrapped in relaxed mode
        for canonical_mode in [True, False]:
            assert convert_from_extjson(convert_to_extjson(value, canonical=canonical_mode)) == value

    # Booleans are not encoded as integers, despite being an int subclass
    assert convert_to_extjson([True, False], canonical=True) == [True, False]


def test_extended_json_decode_invalid_date():

    for valid_extjson in [
        {"dt": {"$date": "1970-01-01T01:00Z"}},
        {"dt": {"$date": "1970-01-01T01+02:00"}},
    ]:
        res = convert_from_extjson(valid_extjson)
        print("VALID DATE PARSED:", res)
        assert res["dt"].year == 1970
        assert res["dt"].tzinfo  # AWARE datetime

    for invalid_extjson_format in [
        {"dt": {"$date": "1970-01-01T00:00:"}},
        {"dt": {"$date": "1970-01-01T01:"}},
        {"dt": {"$date": "1970-01-01T"}},
        {"dt": {"$date": "1970-01-01T"}},
        {"dt": {"$date": "1970-01-"}},
        {"dt": {"$date": "1970-"}},
        {"dt": {"$date": "1970-01"}},
        {"dt": {"$date": "1970"}},
        {"dt": {"$date": ""}},
    ]:
        with pytest.raises(ValueError, match="isoformat"):
            res = convert_from_extjson(invalid_extjson_format)
            print("INVALID DATE PARSED:", res)

    for invalid_extjson_timezone in [
        {"dt": {"$date": "1970-01-01T01:00:22"}},
        {"dt": {"$date": "1970-01-01T01:00"}},
        {"dt": {"$date": "1970-01-01+01:00"}},  # Ignored TZ
    ]:
        with pytest.raises(TypeError, match="naive"):
            res = convert_from_extjson(invalid_extjson_timezone)
            print("INVALID DATE PARSED:", res)


def test_micropython_specific_uuid_and_datetime_decode(monkeypatch):
    # These decode paths are only exercised on real MicroPython, where uuid.UUID
    # and datetime.fromisoformat are thinner stubs than CPython's. Simulate
    # IS_MICROPYTHON here (same pattern as test_json_serialization_sort_keys_handling)
    # so they get covered under CPython CI too.
    monkeypatch.setattr(extjson, "IS_MICROPYTHON", True)

    # $uuid legacy decode goes through binascii.unhexlify(...) + uuid.UUID(bytes=...)
    expected_uid = uuid.UUID("29b91799-7249-4266-a853-80123d7fd684")
    assert convert_from_extjson({"$uuid": "29b9179972494266a85380123d7fd684"}) == expected_uid
    assert convert_from_extjson({"$uuid": "29b91799-7249-4266-a853-80123d7fd684"}) == expected_uid  # Dashes tolerated
    # Same alternative forms as CPython's uuid.UUID(str)
    assert convert_from_extjson({"$uuid": "{29b91799-7249-4266-a853-80123d7fd684}"}) == expected_uid
    assert convert_from_extjson({"$uuid": "urn:uuid:29b91799-7249-4266-a853-80123d7fd684"}) == expected_uid

    # Malformed strings raise the same error as on the CPython uuid.UUID(str) path
    for malformed_uuid in ["nope", "29b9179972494266a85380123d7fd6", "29b9179972494266a85380123d7fd684ab"]:
        with pytest.raises(ValueError, match="badly formed"):
            convert_from_extjson({"$uuid": malformed_uuid})
    with pytest.raises(ValueError):  # Right length, but not hexadecimal
        convert_from_extjson({"$uuid": "zzb9179972494266a85380123d7fd684"})

    # Non-canonical "Z"-suffixed dates go through the "Z" -> "+00:00" substitution;
    # we simulate micropython-lib's fromisoformat, since CPython 3.11+ already supports "Z"
    class _NoZDatetime(datetime):
        @classmethod
        def fromisoformat(cls, date_string):
            if date_string.endswith("Z"):
                raise ValueError(f"Invalid isoformat string: {date_string!r}")
            return datetime.fromisoformat(date_string)

    monkeypatch.setattr(
        extjson, "datetime", types.SimpleNamespace(datetime=_NoZDatetime, timezone=timezone, timedelta=timedelta)
    )
    expected_dt = datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    res = convert_from_extjson({"dt": {"$date": "2024-01-02T03:04:05Z"}})
    assert res["dt"] == expected_dt
    assert res["dt"].tzinfo  # Still aware


def test_epoch_is_unix_epoch():
    # Some Micropython ports use 2000-01-01 as epoch for fromtimestamp(), so it must not be used
    assert extjson._EPOCH_AWARE == datetime(1970, 1, 1, tzinfo=timezone.utc)
    assert convert_to_extjson(datetime(1970, 1, 1, 0, 0, 1, tzinfo=timezone.utc), canonical=True) == {
        "$date": {"$numberLong": "1000"}
    }


def test_import_without_typing_and_decimal_modules(monkeypatch):
    # Simulate a bare Micropython, lacking the typing and decimal modules
    monkeypatch.setitem(sys.modules, "typing", None)
    monkeypatch.setitem(sys.modules, "decimal", None)
    spec = importlib.util.spec_from_file_location("extjson_stripped", extjson.__file__)
    extjson_stripped = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(extjson_stripped)  # Not registered in sys.modules

    assert extjson_stripped.Decimal is extjson_stripped._FakeDecimal

    uid = uuid.UUID("29b91799-7249-4266-a853-80123d7fd684")
    payload = {"a": [1, 2.5, "x"], "b": b"xyz", "c": uid, "d": datetime(2024, 1, 2, tzinfo=timezone.utc)}
    for canonical in [True, False]:
        assert extjson_stripped.load_from_json_str(extjson_stripped.dump_to_json_str(payload, canonical=canonical)) == (
            payload
        )

    # Decimal values can't be decoded, but this only fails lazily, with an explicit error
    with pytest.raises(ImportError, match="decimal"):
        extjson_stripped.convert_from_extjson({"price": {"$numberDecimal": "1.5"}})


def test_float_encoding_fallback_on_lossy_repr(monkeypatch):
    # Simulate Micropython's repr(), which may not round-trip floats
    monkeypatch.setattr(extjson, "repr", lambda value: "%.15g" % value, raising=False)

    value = 0.1 + 0.2
    encoded = convert_to_extjson(value, canonical=True)
    assert encoded == {"$numberDouble": "0.30000000000000004"}
    assert convert_from_extjson(encoded) == value

    assert convert_to_extjson(1.5, canonical=True) == {"$numberDouble": "1.5"}  # Lossless repr is kept


def test_load_json_with_utf8_bom(tmp_path):
    json_bytes = b'\xef\xbb\xbf{"a": 1, "b": {"$uuid": "29b9179972494266a85380123d7fd684"}}'
    expected = {"a": 1, "b": uuid.UUID("29b91799-7249-4266-a853-80123d7fd684")}

    assert load_from_json_bytes(json_bytes) == expected
    assert load_from_json_bytes(bytearray(json_bytes)) == expected

    tmp_filepath = os.path.join(tmp_path, "bom_file.json")
    with open(tmp_filepath, "wb") as f:
        f.write(json_bytes)
    assert load_from_json_file(tmp_filepath) == expected


def test_json_serialization_high_level_utilities(tmp_path):
    uid = uuid.UUID("7c0b18f5-f410-4e83-9263-b38c2328e516")
    payload = dict(b=b"xyz", a="hêllo", c=uid)

    # STRING-level serialization utilities

    serialized_str = dump_to_json_str(payload, canonical=True)
    assert (
        serialized_str  # Keys are sorted
        == (
            r'{"a": "h\u00eallo", "b": {"$binary": {"base64": "eHl6", "subType": "00"}}, '
            r'"c": {"$binary": {"base64": "fAsY9fQQToOSY7OMIyjlFg==", "subType": "04"}}}'
        )
    )
    deserialized = load_from_json_str(serialized_str)
    assert deserialized == payload

    serialized_str = dump_to_json_str(payload, canonical=False)
    assert (
        serialized_str  # Keys are sorted
        == (
            r'{"a": "h\u00eallo", "b": {"$binary": {"base64": "eHl6", "subType": "00"}}, '
            r'"c": {"$uuid": "7c0b18f5f4104e839263b38c2328e516"}}'
        )
    )
    deserialized = load_from_json_str(serialized_str)
    assert deserialized == payload

    serialized_str = dump_to_json_str(payload, canonical=True, ensure_ascii=False)  # Json arguments well propagated
    assert serialized_str == (
        r'{"a": "hêllo", "b": {"$binary": {"base64": "eHl6", "subType": "00"}}, '
        r'"c": {"$binary": {"base64": "fAsY9fQQToOSY7OMIyjlFg==", "subType": "04"}}}'
    )
    deserialized = load_from_json_str(serialized_str)
    assert deserialized == payload

    serialized_str = dump_to_json_str(payload, canonical=False, ensure_ascii=False)  # Json arguments well propagated
    assert serialized_str == (
        r'{"a": "hêllo", "b": {"$binary": {"base64": "eHl6", "subType": "00"}}, '
        r'"c": {"$uuid": "7c0b18f5f4104e839263b38c2328e516"}}'
    )
    deserialized = load_from_json_str(serialized_str)
    assert deserialized == payload

    with pytest.raises(TypeError, match="not JSON serializable"):
        dump_to_json_str({"badtype": timedelta(days=3)}, canonical=_random_bool())

    # BYTES-level serialization utilities

    serialized_str = dump_to_json_bytes(payload, canonical=True)
    assert (
        serialized_str  # Keys are sorted
        == (
            rb'{"a": "h\u00eallo", "b": {"$binary": {"base64": "eHl6", "subType": "00"}}, '
            rb'"c": {"$binary": {"base64": "fAsY9fQQToOSY7OMIyjlFg==", "subType": "04"}}}'
        )
    )
    deserialized = load_from_json_bytes(serialized_str)
    assert deserialized == payload

    serialized_str = dump_to_json_bytes(payload, canonical=True, ensure_ascii=False)  # Json arguments well propagated
    assert serialized_str == (
        b'{"a": "h\xc3\xaallo", "b": {"$binary": {"base64": "eHl6", "subType": "00"}}, '
        b'"c": {"$binary": {"base64": "fAsY9fQQToOSY7OMIyjlFg==", "subType": "04"}}}'
    )
    deserialized = load_from_json_bytes(serialized_str)
    assert deserialized == payload

    serialized_str = dump_to_json_bytes(payload, canonical=False)
    assert (
        serialized_str  # Keys are sorted
        == (
            b'{"a": "h\\u00eallo", "b": {"$binary": {"base64": "eHl6", "subType": "00"}'
            b'}, "c": {"$uuid": "7c0b18f5f4104e839263b38c2328e516"}}'
        )
    )
    deserialized = load_from_json_bytes(serialized_str)
    assert deserialized == payload

    serialized_str = dump_to_json_bytes(payload, canonical=False, ensure_ascii=False)  # Json arguments well propagated
    assert serialized_str == (
        b'{"a": "h\xc3\xaallo", "b": {"$binary": {"base64": "eHl6", "subType": "00"}'
        b'}, "c": {"$uuid": "7c0b18f5f4104e839263b38c2328e516"}}'
    )
    deserialized = load_from_json_bytes(serialized_str)
    assert deserialized == payload

    # FILE-level serialization utilities

    tmp_filepath = os.path.join(tmp_path, "dummy_temp_file.dat")

    serialized_str = dump_to_json_file(
        tmp_filepath, data=payload, canonical=True, ensure_ascii=False
    )  # Json arguments well propagated
    assert serialized_str == (
        b'{"a": "h\xc3\xaallo", "b": {"$binary": {"base64": "eHl6", "subType": "00"}}, '
        b'"c": {"$binary": {"base64": "fAsY9fQQToOSY7OMIyjlFg==", "subType": "04"}}}'
    )
    deserialized = load_from_json_file(tmp_filepath)
    assert deserialized == payload

    serialized_str = dump_to_json_file(
        tmp_filepath, data=payload, canonical=False, ensure_ascii=False
    )  # Json arguments well propagated
    assert serialized_str == (
        b'{"a": "h\xc3\xaallo", "b": {"$binary": {"base64": "eHl6", "subType": "00"}'
        b'}, "c": {"$uuid": "7c0b18f5f4104e839263b38c2328e516"}}'
    )
    deserialized = load_from_json_file(tmp_filepath)
    assert deserialized == payload

    # Special tests for DATES

    utc_date = pytz.utc.localize(datetime(2022, 10, 10))
    pst_date = utc_date.astimezone(pytz.timezone("America/Los_Angeles"))

    payload1 = {"date": utc_date}
    serialized_str1 = dump_to_json_str(payload1, canonical=True)
    payload2 = {"date": pst_date}
    serialized_str2 = dump_to_json_str(payload2, canonical=True)

    assert serialized_str1 == r'{"date": {"$date": {"$numberLong": "1665360000000"}}}'
    assert serialized_str1 == serialized_str2

    deserialized = load_from_json_str(serialized_str1)
    assert deserialized == payload1
    assert deserialized == payload2

    utcoffset = deserialized["date"].utcoffset()
    assert utcoffset == timedelta(0)  # Date is returned as UTC in any case!


def test_json_serialization_sort_keys_handling(monkeypatch):
    payload = {"b": 1, "a": 2}

    assert dump_to_json_str(payload) == '{"a": 2, "b": 1}'  # Sorted by default
    assert dump_to_json_str(payload, sort_keys=False) == '{"b": 1, "a": 2}'  # Can be overridden

    # Micropython's json module doesn't support sort_keys, so it's not set there
    monkeypatch.setattr(extjson, "IS_MICROPYTHON", True)
    assert dump_to_json_str(payload) == '{"b": 1, "a": 2}'


def test_json_serialization_low_level_utilities():

    for extjson_tree in (EXAMPLE_EXTJSON_DATA_TREE_CANONICAL, EXAMPLE_EXTJSON_DATA_TREE_RELAXED):
        example_native_data_tree = copy.deepcopy(EXAMPLE_NATIVE_DATA_TREE)

        json_str = original_dumps(extjson_tree)
        decoded_native_data_tree = original_loads(json_str, object_hook=extjson_decoder_object_hook)

        assert decoded_native_data_tree != example_native_data_tree  # Some little incompatibilities exist
        assert all(math.isnan(x) for x in decoded_native_data_tree["my_nans"])
        del decoded_native_data_tree["my_nans"]
        del example_native_data_tree["my_nans"]

        assert decoded_native_data_tree == example_native_data_tree  # Now equivalent

    # Direct tests for extjson.dumps()/loads() low-level helpers.
    example_native_data_tree = copy.deepcopy(EXAMPLE_NATIVE_DATA_TREE)

    dumped_canonical = dumps(example_native_data_tree, canonical=True, sort_keys=True)
    dumped_relaxed = dumps(example_native_data_tree, canonical=False, sort_keys=True)

    assert original_loads(dumped_canonical) == EXAMPLE_EXTJSON_DATA_TREE_CANONICAL
    assert original_loads(dumped_relaxed) == EXAMPLE_EXTJSON_DATA_TREE_RELAXED

    for dumped in (dumped_canonical, dumped_relaxed, dumped_relaxed.encode("utf8"), bytearray(dumped_relaxed, "utf8")):
        decoded_native_data_tree = loads(dumped)
        expected_native_data_tree = copy.deepcopy(EXAMPLE_NATIVE_DATA_TREE)

        assert decoded_native_data_tree != expected_native_data_tree
        assert all(math.isnan(x) for x in decoded_native_data_tree["my_nans"])
        del decoded_native_data_tree["my_nans"]
        del expected_native_data_tree["my_nans"]

        assert decoded_native_data_tree == expected_native_data_tree


def test_default_canonical_mode_for_all_utilites(tmp_path):
    """
    Check that high-level and low-level utilities all default to canonical=False (i.e relaxed mode).
    """

    expected_native = copy.deepcopy(EXAMPLE_NATIVE_DATA_TREE)

    # Low-level conversion defaults to relaxed mode.
    extjson_default = convert_to_extjson(expected_native)
    assert extjson_default == EXAMPLE_EXTJSON_DATA_TREE_RELAXED
    assert extjson_default == convert_to_extjson(expected_native, canonical=False)

    json_default1 = dumps(expected_native)
    assert json_default1 == dumps(expected_native, canonical=False)

    # High-level serializers also default to relaxed mode.
    json_default2 = dump_to_json_str(expected_native)
    assert json_default2 == dump_to_json_str(expected_native, canonical=False)

    bytes_default = dump_to_json_bytes(expected_native)
    assert bytes_default == dump_to_json_bytes(expected_native, canonical=False)

    filepath = os.path.join(tmp_path, "default_mode.json")
    file_default = dump_to_json_file(filepath, data=expected_native)
    assert file_default == dump_to_json_file(filepath, data=expected_native, canonical=False)

    # Decoders should parse those default-relaxed payloads back to native values.
    decoded_from_str1 = load_from_json_str(json_default1)
    decoded_from_str2 = load_from_json_str(json_default2)
    decoded_from_bytes = load_from_json_bytes(bytes_default)
    decoded_from_file = load_from_json_file(filepath)

    for decoded in (decoded_from_str1, decoded_from_str2, decoded_from_bytes, decoded_from_file):
        assert all(math.isnan(x) for x in decoded["my_nans"])
        del decoded["my_nans"]

        expected_without_nans = copy.deepcopy(expected_native)
        del expected_without_nans["my_nans"]
        assert decoded == expected_without_nans
