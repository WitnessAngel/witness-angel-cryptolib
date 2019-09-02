"""waserver URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

import jsonrpc.views
from django.conf.urls import url
from jsonrpc import jsonrpc_site

from . import views  # Register methods
del views

urlpatterns = [
    url(r"^json/browse/", jsonrpc.views.browse, name="jsonrpc_browser"),
    url(r"^json/", jsonrpc_site.dispatch, name="jsonrpc_mountpoint"),
    url(r"^json/(?P<method>[a-zA-Z0-9.]+)$", jsonrpc_site.dispatch, name="jsonrpc_getter_mountpoint"),
]
