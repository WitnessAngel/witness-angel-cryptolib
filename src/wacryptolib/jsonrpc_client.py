from jsonrpc_requests import Server as ServerBase, ProtocolError

from wacryptolib.utilities import dump_to_json_str, load_from_json_str


class JsonRpcProxy(ServerBase):
    """A connection to a HTTP JSON-RPC server, backed by the `requests` library.

    See https://github.com/gciotta/jsonrpc-requests for usage examples.

    The differences between our `JsonRpcProxy` and upstream's `Server` class are:

    - we dump/load data using Pymongo's Extended Json format, able to transparently deal with bytes, uuids, dates etc.
    - we do not auto-unpack single dict arguments on call, e.g `proxy.foo({'fizz': 1, 'fuzz': 2})` will be treated as
      calling remote foo() with a single dict argument, not as passing it keyword arguments `fizz` and `fuzz`.

    """

    @staticmethod
    def dumps(data):
        """We override to use Extended Json here."""
        return dump_to_json_str(data)

    @staticmethod
    def parse_response(response):
        """We override to use Extended Json here."""

        def custom_json_decoder():
            return load_from_json_str(response.text)

        response.json = custom_json_decoder
        return ServerBase.parse_response(response)

    # We override ultra-private Server.__request() method!
    def _Server__request(self, method_name, args=None, kwargs=None):
        """Perform the actual RPC call. If _notification=True, send a notification and don't wait for a response"""
        is_notification = kwargs.pop("_notification", False)
        if args and kwargs:
            raise ProtocolError(
                    "JSON-RPC spec forbids mixing arguments and keyword arguments"
            )

        # NOPE WE DISABLE THIS AMBIGUOUS NORMALIZATION!
        # from the specs:
        # "If resent, parameters for the rpc call MUST be provided as a Structured value.
        #  Either by-position through an Array or by-name through an Object."
        # if len(args) == 1 and isinstance(args[0], collections.Mapping):
        #    args = dict(args[0])

        return self.send_request(method_name, is_notification, args or kwargs)
