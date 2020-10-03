import json
import uuid
from base64 import b64encode

import pytest
import responses
from jsonrpc_requests import ProtocolError

from wacryptolib.jsonrpc_client import JsonRpcProxy, status_slugs_response_error_handler


@responses.activate
def test_jsonrpc_extended_json_calls():

    uid = uuid.UUID("450fc293-b702-42d3-ae65-e9cc58e5a62a")

    server = JsonRpcProxy("http://mock/xmlrpc", response_error_handler=None)

    # rpc call with positional args
    def callback1(request):
        request_message = json.loads(request.body)
        assert request_message["params"] == [
            {"$numberInt": "42"},
            {"$binary": {"base64": b64encode(b"xyz").decode("ascii"), "subType": "00"}},
            {"$binary": {"base64": "RQ/Ck7cCQtOuZenMWOWmKg==", "subType": "03"}},
        ]
        return (
            200,
            {},
            u'{"jsonrpc": "2.0", "result": {"$binary": {"base64": "RQ/Ck7cCQtOuZenMWOWmKg==", "subType": "03"}}, "id": 1}',
        )

    responses.add_callback(responses.POST, "http://mock/xmlrpc", content_type="application/json", callback=callback1)
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
        return (200, {}, u'{"jsonrpc": "2.0", "result": {"$binary": {"base64": "eHl6", "subType": "00"}}, "id": 1}')

    responses.add_callback(responses.POST, "http://mock/xmlrpc", content_type="application/json", callback=callback2)
    assert server.foobar(x=42, y=b"xyz", z=uid) == b"xyz"
    responses.reset()

    # rpc call with a mapping type -> we disabled auto unpacking of arguments!!
    def callback3(request):
        request_message = json.loads(request.body)
        assert request_message["params"] == [{"foo": "bar"}]  # remains a LIST of 1 positional parameter!
        return 200, {}, u'{"jsonrpc": "2.0", "result": null}'

    responses.add_callback(responses.POST, "http://mock/xmlrpc", content_type="application/json", callback=callback3)
    assert server.foobar({"foo": "bar"}) is None
    responses.reset()

    with pytest.raises(ProtocolError, match="spec forbids mixing arguments and keyword arguments"):
        server.foobar(33, a=22)

    def callback_protocol_error(request):
        return (200, {}, u'{"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}, "id": null}')

    # Test exception handling

    responses.add_callback(
        responses.POST, "http://mock/xmlrpc", content_type="application/json", callback=callback_protocol_error
    )
    with pytest.raises(ProtocolError, match="Error: -32700 Parse error"):
        server.foobar({"foo": "bar"})

    must_raise = True

    def _response_error_handler(exc_to_handle):
        nonlocal must_raise
        if not must_raise:
            return "some error occurred"
        raise RuntimeError(str(exc_to_handle))

    server = JsonRpcProxy("http://mock/xmlrpc", response_error_handler=_response_error_handler)

    with pytest.raises(RuntimeError, match="Error: -32700 Parse error"):
        server.foobar({"foo": "bar"})

    must_raise = False

    assert server.foobar({"foo": "bar"}) == "some error occurred"

    responses.reset()


def test_status_slugs_response_error_handler():

    exc = ProtocolError(
        "problems occurred",
        server_data={
            "error": {
                "code": 400,
                "data": {"data": None, "message_untranslated": "bigfailure", "status_slugs": ["RuntimeError"]},
            }
        },
    )
    with pytest.raises(RuntimeError, match="bigfailure"):
        status_slugs_response_error_handler(exc)

    exc = ProtocolError(
        "problems occurred",
        server_data={
            "error": {
                "code": 400,
                "data": {"data": None, "message_untranslated": "bigfailure", "status_slugs": ["UnknownClass"]},
            }
        },
    )
    with pytest.raises(Exception, match="bigfailure") as exc_info:
        status_slugs_response_error_handler(exc)
    assert exc_info.type is Exception  # Not a subclass, here

    exc = ProtocolError("problems occurred", server_data={"error": {"code": 400, "data": None}})
    with pytest.raises(ProtocolError, match="problems occurred"):
        status_slugs_response_error_handler(exc)
