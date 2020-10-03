import builtins
import logging

from jsonrpc_requests import Server as ServerBase, ProtocolError

from wacryptolib.error_handling import StatusSlugsMapper
from wacryptolib.utilities import dump_to_json_str, load_from_json_str
from wacryptolib import exceptions as wacryptolib_exceptions

logger = logging.getLogger(__name__)


# FIXME create helper tools to simplify this!

_exception_classes = StatusSlugsMapper.gather_exception_subclasses(builtins, parent_classes=[Exception])
_exception_classes += StatusSlugsMapper.gather_exception_subclasses(
    wacryptolib_exceptions, parent_classes=[wacryptolib_exceptions.FunctionalError]
)

exception_mapper = StatusSlugsMapper(_exception_classes, fallback_exception_class=Exception)


def status_slugs_response_error_handler(exc):
    """
    Generic error handler which recognizes status slugs of builtin exceptions in json-rpc error responses,
    and reraises them client-side.
    """
    assert isinstance(exc, ProtocolError), exc
    error_data = exc.server_data["error"]["data"]
    if error_data:
        status_slugs = error_data["status_slugs"]
        status_message = error_data["message_untranslated"]
        exception_class = exception_mapper.get_closest_exception_class_for_status_slugs(status_slugs)
        raise exception_class(status_message) from exc
    raise exc from None


class JsonRpcProxy(ServerBase):
    """A connection to a HTTP JSON-RPC server, backed by the `requests` library.

    See https://github.com/gciotta/jsonrpc-requests for usage examples.

    The differences between our `JsonRpcProxy` and upstream's `Server` class are:

    - we dump/load data using Pymongo's Extended Json format, able to transparently deal with bytes, uuids, dates etc.
    - we do not auto-unpack single dict arguments on call, e.g `proxy.foo({'fizz': 1, 'fuzz': 2})` will be treated as
      calling remote foo() with a single dict argument, not as passing it keyword arguments `fizz` and `fuzz`.
    - a `response_error_handler` callback can be provided to swallow or convert an error received in an RPC response.

    """

    def __init__(self, url, *args, response_error_handler=None, **kwargs):
        super().__init__(url, *args, **kwargs)
        self._url = url
        self._response_error_handler = response_error_handler

    @staticmethod
    def dumps(data):
        """We override to use Extended Json here."""
        return dump_to_json_str(data)

    def parse_response(self, response):
        """We override to use Extended Json here."""

        def custom_json_decoder():
            return load_from_json_str(response.text)

        response.json = custom_json_decoder
        try:
            return ServerBase.parse_response(response)
        except ProtocolError as exc:
            if self._response_error_handler:
                return self._response_error_handler(exc)
            raise

    # We override ultra-private Server.__request() method!
    def _Server__request(self, method_name, args=None, kwargs=None):
        """Perform the actual RPC call. If _notification=True, send a notification and don't wait for a response"""
        is_notification = kwargs.pop("_notification", False)
        if args and kwargs:
            raise ProtocolError("JSON-RPC spec forbids mixing arguments and keyword arguments")

        # NOPE WE DISABLE THIS AMBIGUOUS NORMALIZATION!
        # from the specs:
        # "If resent, parameters for the rpc call MUST be provided as a Structured value.
        #  Either by-position through an Array or by-name through an Object."
        # if len(args) == 1 and isinstance(args[0], collections.Mapping):
        #    args = dict(args[0])

        logger.info("Initiating remote call '%s()' to server %s", method_name, self._url)
        return self.send_request(method_name, is_notification, args or kwargs)
