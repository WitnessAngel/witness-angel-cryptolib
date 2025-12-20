import copy
import decimal
import random
from pprint import pprint
import unittest, os, sys, pytz
from typing import Tuple, Type, Any

import pytest

sys.path.append(os.path.dirname(__file__))

from decimal import Decimal
from datetime import datetime, timedelta, timezone
from json import JSONDecodeError

from extended_json import loads, dumps, convert_to_extjson, convert_from_extjson
from wacryptolib.exceptions import SchemaValidationError
from wacryptolib.utilities import UTF8_ENCODING
import uuid
import math


def _random_bool():
    return bool(random.getrandbits(1))


EXAMPLE_NATIVE_DATA_TREE = {
    "my_none": None,
    "my_bools": {"OK": True, "KO": False},
    "my_strs": ["", "abc", "hêll@\nällz"],
    "my_nans": [math.nan, Decimal("NaN")],
    "my_ints": [-197282632562525242626256252625, -11, 0, 27627262727, 273262853882627266372772373772646252624542543],
    "my_floats": [-math.inf, -138262872.27267262123456, -20.001, -17.0, -0.0, 0.0, 2.0, 411.1234567890000002, 2276372572.15, math.inf],
    "my_decimals": [Decimal("-Infinity"), Decimal("-138262872.272672622927825262262426245242524"), Decimal("-22.001"),
                    Decimal("-3.0"), Decimal("-0.0"), Decimal("0.0"), Decimal("4.0"), Decimal("282872.2"), Decimal("2276372572.152926382527252762522265262"), Decimal("Infinity")],
    "my_dates": [datetime(1, 1, 1, tzinfo=pytz.utc),
                 datetime(2025, 10, 22, 2, 3, 4, 543000,
                          tzinfo=pytz.timezone('Pacific/Johnston'))],
    "my_uids": [uuid.UUID("29b91799-7249-4266-a853-80123d7fd684"), uuid.UUID("29b91799-7249-4266-a853-80123d7fd684")],
    "my_bytes": [b"", b"hello world", b"\x00\x01\x02\x03\x04\x05\xfa\xfb\xfc\xfd\xfe\xff"],
}


def test_extended_json_tree_encode_decode_in_canonical_mode():

    example_native_data_tree = copy.deepcopy(EXAMPLE_NATIVE_DATA_TREE)

    ext_json = convert_to_extjson(example_native_data_tree, canonical=True)
    print("EXTJSON DUMP CANONICAL:") ; pprint(ext_json)

    expected_ext_json = {'my_bools': {'KO': False, 'OK': True},
                         'my_bytes': [{'$binary': {'base64': '', 'subType': '00'}},
                                      {'$binary': {'base64': 'aGVsbG8gd29ybGQ=', 'subType': '00'}},
                                      {'$binary': {'base64': 'AAECAwQF+vv8/f7/', 'subType': '00'}}],
                         'my_dates': [{'$date': {'$numberLong': '-62135596800000'}},
                                      {'$date': {'$numberLong': '1761136444543'}}],
                         'my_nans': [{'$numberDouble': 'NaN'}, {'$numberDecimal': 'NaN'}],  # Never equal to anything
                         'my_floats': [{'$numberDouble': '-Infinity'},
                                       {'$numberDouble': '-138262872.27267262'},  # TRUNCATED by Python
                                       {'$numberDouble': '-20.001'},
                                       {'$numberDouble': '-17.0'},
                                       {'$numberDouble': '-0.0'},
                                       {'$numberDouble': '0.0'},
                                       {'$numberDouble': '2.0'},
                                       {'$numberDouble': '411.123456789'},
                                       {'$numberDouble': '2276372572.15'},  # TRUNCATED by Python
                                       {'$numberDouble': 'Infinity'}],
                         'my_decimals': [
                             {
                                 '$numberDecimal': '-Infinity',
                             },
                             {
                                 '$numberDecimal': '-138262872.272672622927825262262426245242524',
                             },
                             {
                                 '$numberDecimal': '-22.001',
                             },
                             {
                                 '$numberDecimal': '-3.0',
                             },
                             {
                                 '$numberDecimal': '-0.0',
                             },
                             {
                                 '$numberDecimal': '0.0',
                             },
                             {
                                 '$numberDecimal': '4.0',
                             },
                             {
                                 '$numberDecimal': '282872.2',
                             },
                             {
                                 '$numberDecimal': '2276372572.152926382527252762522265262',
                             },
                             {
                                 '$numberDecimal': 'Infinity',
                             }],

                         'my_ints': [{'$numberLong': '-197282632562525242626256252625'},
                                     {'$numberInt': '-11'},
                                     {'$numberInt': '0'},
                                     {'$numberLong': '27627262727'},
                                     {'$numberLong': '273262853882627266372772373772646252624542543'}],
                         'my_none': None,
                         'my_strs': ['', 'abc', 'hêll@\nällz'],
                         'my_uids': [{'$binary': {'base64': 'KbkXmXJJQmaoU4ASPX/WhA==',
                                                  'subType': '04'}},
                                     {'$binary': {'base64': 'KbkXmXJJQmaoU4ASPX/WhA==',
                                                  'subType': '04'}}]}

    assert ext_json == expected_ext_json

    decoded_native_data_tree = convert_from_extjson(ext_json)
    print("DECODED NATIVE DUMP:") ; pprint(decoded_native_data_tree)

    assert decoded_native_data_tree != example_native_data_tree  # Some little incompatibilities exist
    assert all(math.isnan(x) for x in decoded_native_data_tree["my_nans"])

    del decoded_native_data_tree["my_nans"]
    del example_native_data_tree["my_nans"]

    assert decoded_native_data_tree == {
         'my_bools': {'KO': False, 'OK': True},
         'my_bytes': [b'',
                      b'hello world',
                      b'\x00\x01\x02\x03\x04\x05\xfa\xfb\xfc\xfd\xfe\xff'],
         'my_dates': [datetime(1, 1, 1, 0, 0, tzinfo=pytz.utc),
                      datetime(2025, 10, 22, 12, 34, 4, 543000,
                               tzinfo=pytz.utc)],  # Timezone was changed!

         'my_ints': [-197282632562525242626256252625,
                     -11,
                     0,
                     27627262727,
                     273262853882627266372772373772646252624542543],
        'my_floats': [-math.inf,
                      -138262872.27267262,
                      -20.001,
                      -17.0,
                      -0.0,
                      0.0,
                      2.0,
                      411.123456789,
                      2276372572.15,
                      math.inf],
        'my_decimals': [
                Decimal('-Infinity'),
                Decimal('-138262872.272672622927825262262426245242524'),
                Decimal('-22.001'),
                Decimal('-3.0'),
                Decimal('-0.0'),
                Decimal('0.0'),
                Decimal('4.0'),
                Decimal('282872.2'),
                Decimal('2276372572.152926382527252762522265262'),
                Decimal('Infinity')],

         'my_none': None,
         'my_strs': ['', 'abc', 'hêll@\nällz'],
         'my_uids': [uuid.UUID('29b91799-7249-4266-a853-80123d7fd684'),
                     uuid.UUID('29b91799-7249-4266-a853-80123d7fd684')]}

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


def test_extended_json_tree_encode_decode_in_relaxed_mode():

    example_native_data_tree = copy.deepcopy(EXAMPLE_NATIVE_DATA_TREE)

    ext_json = convert_to_extjson(example_native_data_tree, canonical=False)
    print("EXTJSON DUMP RELAXED:") ; pprint(ext_json)

    expected_ext_json = {
         'my_bools': {'KO': False, 'OK': True},
         'my_bytes': [{'$binary': {'base64': '', 'subType': '00'}},  # Always canonical for bytes
                      {'$binary': {'base64': 'aGVsbG8gd29ybGQ=', 'subType': '00'}},
                      {'$binary': {'base64': 'AAECAwQF+vv8/f7/', 'subType': '00'}}],
         'my_dates': [{'$date': '0001-01-01T00:00:00Z'},
                      {'$date': '2025-10-22T02:03:04.543-10:31'}],
         'my_decimals': [{'$numberDecimal': '-Infinity'},
                         {'$numberDecimal': '-138262872.272672622927825262262426245242524'},
                         {'$numberDecimal': '-22.001'},
                         {'$numberDecimal': '-3.0'},
                         {'$numberDecimal': '-0.0'},
                         {'$numberDecimal': '0.0'},
                         {'$numberDecimal': '4.0'},
                         {'$numberDecimal': '282872.2'},
                         {'$numberDecimal': '2276372572.152926382527252762522265262'},
                         {'$numberDecimal': 'Infinity'}],
         'my_floats': [{'$numberDouble': '-Infinity'},
                       -138262872.27267262,
                       -20.001,
                       -17.0,
                       -0.0,
                       0.0,
                       2.0,
                       411.123456789,
                       2276372572.15,
                       {'$numberDouble': 'Infinity'}],
         'my_ints': [-197282632562525242626256252625,
                     -11,
                     0,
                     27627262727,
                     273262853882627266372772373772646252624542543],
        'my_nans': [{'$numberDouble': 'NaN'}, {'$numberDecimal': 'NaN'}],  # Never equal to anything
         'my_none': None,
         'my_strs': ['', 'abc', 'hêll@\nällz'],
         'my_uids': [{'$uuid': '29b9179972494266a85380123d7fd684'},
                     {'$uuid': '29b9179972494266a85380123d7fd684'}]}


    assert ext_json == expected_ext_json

    decoded_native_data_tree = convert_from_extjson(ext_json)
    print("DECODED NATIVE DUMP:") ; pprint(decoded_native_data_tree)

    assert decoded_native_data_tree != example_native_data_tree  # Some little incompatibilities exist
    assert all(math.isnan(x) for x in decoded_native_data_tree["my_nans"])

    del decoded_native_data_tree["my_nans"]
    del example_native_data_tree["my_nans"]

    assert decoded_native_data_tree == {
        'my_bools': {
            'KO': False,
            'OK': True,
        },
        'my_bytes': [
            b'',
            b'hello world',
            b'\x00\x01\x02\x03\x04\x05\xfa\xfb\xfc\xfd\xfe\xff',
        ],
        'my_dates': [datetime(1, 1, 1, 0, 0, tzinfo=pytz.utc),
                     datetime(2025, 10, 22, 12, 34, 4, 543000,
                              tzinfo=pytz.utc)],  # Equivalent
        'my_decimals': [
            Decimal('-Infinity'),
            Decimal('-138262872.272672622927825262262426245242524'),
            Decimal('-22.001'),
            Decimal('-3.0'),
            Decimal('-0.0'),
            Decimal('0.0'),
            Decimal('4.0'),
            Decimal('282872.2'),
            Decimal('2276372572.152926382527252762522265262'),
            Decimal('Infinity'),
        ],
        'my_floats': [
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
        'my_ints': [
            -197282632562525242626256252625,
            -11,
            0,
            27627262727,
            273262853882627266372772373772646252624542543,
        ],
        'my_none': None,
        'my_strs': [
            '',
            'abc',
            'hêll@\n'
            'ällz',
        ],
        'my_uids': [
            uuid.UUID('29b91799-7249-4266-a853-80123d7fd684'),
            uuid.UUID('29b91799-7249-4266-a853-80123d7fd684'),
        ],
    }

    assert decoded_native_data_tree == example_native_data_tree  # ROUND-TRIP EQUALITY AFTER REMOVING NaN


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



def test_extended_json_specific_cases():

    assert convert_from_extjson({"$undefined": True}) is None
    assert convert_from_extjson({"$undefined": False}) is None

    # If conversion is impossible, we just let the object as is
    input = {"unsupported": timedelta(days=3)}
    assert convert_to_extjson(input, canonical=True) == input
    assert convert_to_extjson(input, canonical=False) == input

    with pytest.raises(TypeError, match="naive"):
        convert_to_extjson(datetime(2024, 1, 16, 0, 0, 0, 0),
                           canonical=_random_bool())


def test_extended_json_undecodable_payloads():

    # The presence of other keys blocks extjson decoding
    skipped_payloads = [
        {"$date": "something", "somekey": True},
         {"$binary": "something","somekey": True},
          {"$uuid":  "something","somekey": True},
           {"$undefined": "something","somekey": True},
            {"$numberInt": "something","somekey": True},
             {"$numberLong": "something","somekey": True},
              {"$numberDouble": "something","somekey": True},
               {"$numberDecimal": "something","somekey": True},
    ]
    for skipped_payload in skipped_payloads:
        assert convert_to_extjson(skipped_payload, canonical=_random_bool()) == skipped_payload

    broken_payloads = [
        {"$date": 3.12},
         {"$binary": 42},
         {"$binary": {"badkey": True}},
         {"$binary": {"base64": "736", "subType": "00", "badkey": True}},
         {"$binary": {"base64": 333, "subType": "00",}},
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
        convert_from_extjson({"$binary": {"base64": "QUI=", "subType": "01",}},)


def test_extended_json_decode_invalid_date():

    for valid_extjson in [
        {"dt": { "$date" : "1970-01-01T01:00"}},
        {"dt": { "$date" : "1970-01-01T01"}},
        {"dt": { "$date" : "1970-01-01"}},
    ]:
        res = convert_from_extjson(valid_extjson)
        print("VALID DATE PARSED:", res)
        assert res["dt"].year == 1970

    # These cases should raise ValueError, not IndexError.
    for invalid_extjson in [
        {"dt": { "$date" : "1970-01-01T00:00:"}},
        {"dt": { "$date" : "1970-01-01T01:"}},
        {"dt": { "$date" : "1970-01-01T"}},
        {"dt": { "$date" : "1970-01-01T"}},
        {"dt": { "$date" : "1970-01-"}},
        {"dt": { "$date" : "1970-"}},
        {"dt": { "$date" : "1970-01"}},
        {"dt": { "$date" : "1970"}},
        {"dt": { "$date" : ""}},
    ]:
        with pytest.raises(ValueError, match="isoformat"):
            res = convert_from_extjson(invalid_extjson)
            print("INVALID DATE PARSED:", res)


def dump_to_json_str(data, **extra_options):
    """
    Dump a data tree to a json representation as string.
    Supports advanced types like bytes, uuids, dates...
    """
    sort_keys = extra_options.pop("sort_keys", True)
    json_str = dumps(data, sort_keys=sort_keys, **extra_options)
    return json_str


def load_from_json_str(data, **extra_options):
    """
    Load a data tree from a json representation as string.
    Supports advanced types like bytes, uuids, dates...

    Raises exceptions.ValidationError on loading error.
    """
    assert isinstance(data, str), data
    try:
        return loads(data, **extra_options)
    except JSONDecodeError as exc:
        raise SchemaValidationError("Invalid JSON string: %r" % exc) from exc


def dump_to_json_bytes(data, **extra_options):
    """
    Same as `dump_to_json_str`, but returns UTF8-encoded bytes.
    """
    json_str = dump_to_json_str(data, **extra_options)
    return json_str.encode(UTF8_ENCODING)


def load_from_json_bytes(data, **extra_options):
    """
    Same as `load_from_json_str`, but takes UTF8-encoded bytes as input.
    """

    json_str = data.decode(UTF8_ENCODING)
    return load_from_json_str(data=json_str, **extra_options)


def dump_to_json_file(filepath, data, **extra_options):
    """
    Same as `dump_to_json_bytes`, but writes data to filesystem (and returns bytes too).
    """
    json_bytes = dump_to_json_bytes(data, **extra_options)
    with open(filepath, "wb") as f:
        f.write(json_bytes)
    return json_bytes


def load_from_json_file(filepath, **extra_options):
    """
    Same as `load_from_json_bytes`, but reads data from filesystem.
    """
    with open(filepath, "rb") as f:
        json_bytes = f.read()
    return load_from_json_bytes(json_bytes, **extra_options)




def test_serialization_utilities(tmp_path):
    uid = uuid.UUID("7c0b18f5-f410-4e83-9263-b38c2328e516")
    payload = dict(b=b"xyz", a="hêllo", c=uid)

    serialized_str = dump_to_json_str(payload)
    # Keys are sorted
    assert (
        serialized_str
        == r'{"a": "h\u00eallo", "b": {"$binary": {"base64": "eHl6", "subType": "00"}}, "c": {"$binary": {"base64": "fAsY9fQQToOSY7OMIyjlFg==", "subType": "04"}}}'
    )
    deserialized = load_from_json_str(serialized_str)
    assert deserialized == payload

    serialized_str = dump_to_json_str(payload, ensure_ascii=False)  # Json arguments well propagated
    assert (
        serialized_str
        == r'{"a": "hêllo", "b": {"$binary": {"base64": "eHl6", "subType": "00"}}, "c": {"$binary": {"base64": "fAsY9fQQToOSY7OMIyjlFg==", "subType": "04"}}}'
    )
    deserialized = load_from_json_str(serialized_str)
    assert deserialized == payload

    serialized_str = dump_to_json_bytes(payload)
    # Keys are sorted
    assert (
        serialized_str
        == rb'{"a": "h\u00eallo", "b": {"$binary": {"base64": "eHl6", "subType": "00"}}, "c": {"$binary": {"base64": "fAsY9fQQToOSY7OMIyjlFg==", "subType": "04"}}}'
    )
    deserialized = load_from_json_bytes(serialized_str)
    assert deserialized == payload

    serialized_str = dump_to_json_bytes(payload, ensure_ascii=False)  # Json arguments well propagated
    assert (
        serialized_str
        == b'{"a": "h\xc3\xaallo", "b": {"$binary": {"base64": "eHl6", "subType": "00"}}, "c": {"$binary": {"base64": "fAsY9fQQToOSY7OMIyjlFg==", "subType": "04"}}}'
    )
    deserialized = load_from_json_bytes(serialized_str)
    assert deserialized == payload

    tmp_filepath = os.path.join(tmp_path, "dummy_temp_file.dat")
    serialized_str = dump_to_json_file(tmp_filepath, data=payload, ensure_ascii=True)  # Json arguments well propagated
    assert (
        serialized_str
        == rb'{"a": "h\u00eallo", "b": {"$binary": {"base64": "eHl6", "subType": "00"}}, "c": {"$binary": {"base64": "fAsY9fQQToOSY7OMIyjlFg==", "subType": "04"}}}'
    )
    deserialized = load_from_json_file(tmp_filepath)
    assert deserialized == payload

    # Special tests for DATES

    utc_date = pytz.utc.localize(datetime(2022, 10, 10))
    pst_date = utc_date.astimezone(pytz.timezone("America/Los_Angeles"))

    payload1 = {"date": utc_date}
    serialized_str1 = dump_to_json_str(payload1)
    payload2 = {"date": pst_date}
    serialized_str2 = dump_to_json_str(payload2)

    assert serialized_str1 == r'{"date": {"$date": {"$numberLong": "1665360000000"}}}'
    assert serialized_str1 == serialized_str2

    deserialized = load_from_json_str(serialized_str1)
    assert deserialized == payload1
    assert deserialized == payload2

    utcoffset = deserialized["date"].utcoffset()
    assert utcoffset == timedelta(0)  # Date is returned as UTC in any case!

