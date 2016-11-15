#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    hook.py

    A Simple HTTP Proxy Server in Python.
    :copyright: (c) 2016 by nkwsqyyzx@gmail.com
    :license: BSD, see LICENSE for more details.
"""

from SimpleProxyServer import ReadWriteHook
from SimpleProxyServer import TYPE_HOOK_CLIENT_DOWN, TYPE_HOOK_SERVER_UP


# noinspection PyAbstractClass
class _InnerHook(ReadWriteHook):
    def __init__(self, hook_type):
        super(_InnerHook, self).__init__(hook_type)
        self.hooks = []

    def add_hook(self, hook):
        self.hooks.append(hook)

    def should_rewrite(self, client_parser, server_parser):
        raise NotImplementedError()


# noinspection PyAbstractClass
class ClientSideHook(_InnerHook):
    def __init__(self):
        super(ClientSideHook, self).__init__(TYPE_HOOK_CLIENT_DOWN)

    def _enable_rewrite_client_request(self, client_parser, server_parser):
        return None

    def _enable_rewrite_server_response(self, client_parser, server_parser):
        for hook in self.hooks:
            enable = hook.should_rewrite(client_parser, server_parser)
            if enable:
                return hook
        return None


class _ClientHooks(ClientSideHook):
    def should_rewrite(self, client_parser, server_parser):
        raise Exception('should not call this function')

    def rewrite_body(self, body):
        raise Exception('should not call this function')

    def rewrite_headers(self, headers):
        raise Exception('should not call this function')


# noinspection PyAbstractClass
class ServerSideHook(_InnerHook):
    def __init__(self):
        super(ServerSideHook, self).__init__(TYPE_HOOK_SERVER_UP)

    def _enable_rewrite_client_request(self, client_parser, server_parser):
        for hook in self.hooks:
            enable = hook.should_rewrite(client_parser, server_parser)
            if enable:
                return hook
        return None

    def _enable_rewrite_server_response(self, client_parser, server_parser):
        return None


class _ServerHooks(ServerSideHook):
    def should_rewrite(self, client_parser, server_parser):
        raise Exception('should not call this function')

    def rewrite_body(self, body):
        raise Exception('should not call this function')

    def rewrite_headers(self, headers):
        raise Exception('should not call this function')


class TestResponseHook(ClientSideHook):
    def rewrite_body(self, body):
        return 'holly shit'

    def rewrite_headers(self, headers):
        pass

    def should_rewrite(self, client_parser, server_parser):
        url = client_parser.url or None
        hostname = url.hostname if url else ''
        return 'not.https.name' in (hostname or '')


_client_hook = _ClientHooks()
CLIENT_HOOK = _client_hook
_server_hook = _ServerHooks()
SERVER_HOOK = _server_hook


_client_hook.add_hook(TestResponseHook())
