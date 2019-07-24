from jsonrpc import jsonrpc_method


@jsonrpc_method('sayhelloworld')
def helloworld(request):
    return "Hello world"
