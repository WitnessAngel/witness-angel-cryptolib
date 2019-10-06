import json
import uuid
from base64 import b64encode

import pytest
import responses
from jsonrpc_requests import ProtocolError

from wacryptolib.jsonrpc_client import JsonRpcProxy


@responses.activate
def test_jsonrpc_extended_json_calls():

    uid = uuid.UUID("450fc293-b702-42d3-ae65-e9cc58e5a62a")

    server = JsonRpcProxy("http://mock/xmlrpc")

    # rpc call with positional args
    def callback1(request):
        request_message = json.loads(request.body)
        assert request_message["params"] == [
            {"$numberInt": "42"},
            {"$binary": {"base64": b64encode(b"xyz").decode("ascii"), "subType": "00"}},
            {"$binary": {"base64": "RQ/Ck7cCQtOuZenMWOWmKg==", "subType": "03"}},
        ]
        return 200, {}, u'{"jsonrpc": "2.0", "result": {"$binary": {"base64": "RQ/Ck7cCQtOuZenMWOWmKg==", "subType": "03"}}, "id": 1}'

    responses.add_callback(
        responses.POST,
        "http://mock/xmlrpc",
        content_type="application/json",
        callback=callback1,
    )
    assert server.foobar(42, b"xyz", uid) == uid
    responses.reset()

    # rpc call with named parameters
    def callback2(request):
        request_message = json.loads(request.body)
        assert request_message["params"] == {
            "x": {"$numberInt": "42"},
            "y": {"$binary": {"base64": "eHl6", "subType": "00"}},
            "z": {"$binary": {"base64": "RQ/Ck7cCQtOuZenMWOWmKg==", "subType": "03"}},
        }
        return 200, {}, u'{"jsonrpc": "2.0", "result": {"$binary": {"base64": "eHl6", "subType": "00"}}, "id": 1}'

    responses.add_callback(
        responses.POST,
        "http://mock/xmlrpc",
        content_type="application/json",
        callback=callback2,
    )
    assert server.foobar(x=42, y=b"xyz", z=uid) == b"xyz"
    responses.reset()

    # rpc call with a mapping type -> we disabled auto unpacking of arguments!!
    def callback3(request):
        request_message = json.loads(request.body)
        assert request_message["params"] == [
            {"foo": "bar"}
        ]  # remains a LIST of 1 positional parameter!
        return 200, {}, u'{"jsonrpc": "2.0", "result": null}'

    responses.add_callback(
        responses.POST,
        "http://mock/xmlrpc",
        content_type="application/json",
        callback=callback3,
    )
    assert server.foobar({"foo": "bar"}) is None
    responses.reset()

    with pytest.raises(ProtocolError, match="spec forbids mixing arguments and keyword arguments"):
        server.foobar(33, a=22)
