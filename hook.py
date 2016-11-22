#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    hook.py

    A Simple HTTP Proxy Server in Python.
    :copyright: (c) 2016 by nkwsqyyzx@gmail.com
    :license: BSD, see LICENSE for more details.
"""
import logging

from constants import *

log = logging.getLogger(__name__)


class Context(object):
    def __init__(self):
        object.__setattr__(self, '_dict', {})

    def __getattr__(self, item):
        return self._dict.get(item)

    def __setattr__(self, key, value):
        self._dict[key] = value


class ReadWriteHook(object):
    def rewrite_client_request(self, client_parser, server_parser):
        """:return modified client_parser to enable hook"""
        raise NotImplementedError()

    def rewrite_server_response(self, client_parser, server_parser):
        """:return modified server_parser to enable hook"""
        raise NotImplementedError()

    def _respond(self, request_parser, response_parser):
        if request_parser.context.respond_hook == self:
            return True
        v = self.respond(request_parser, response_parser)
        if v:
            request_parser.context.respond_hook = self
        return v

    def respond(self, request_parser, response_parser):
        raise NotImplementedError()

    def rebuild(self, side, request_parser, response_parser):
        if side == 0:
            new_parser = self.rewrite_server_response(request_parser, response_parser)
        else:
            new_parser = self.rewrite_client_request(request_parser, response_parser)
        return ReadWriteHook._rebuild(new_parser) if new_parser else None

    @staticmethod
    def _rebuild(new_parser):
        bodies = []
        arr = []
        body_type, new_body = new_parser.type_body
        if new_body:
            if body_type == TYPE_BODY_CHUNK:
                bodies.append(hex(len(new_body))[2:])
                bodies.append(new_body)
                bodies.append(b'0')
                bodies.append(CRLF)
            elif body_type == TYPE_BODY_MULTIPART:
                boundary = b'--' + new_parser.multipart_parser.boundary
                names = new_parser.multipart_parser.names
                # body is a dict with k -> (raw_body, multipart)
                for k in names:
                    bodies.append(boundary)
                    for (_, h) in enumerate(new_body[k][1].headers.items()):
                        bodies.append(h[0].encode('utf8') + COLON + SPACE + h[1].encode('utf8'))
                    bodies.append(b'')
                    bodies.append(new_body[k][0])
                bodies.append(boundary + b'--')
                bodies.append('')
            else:
                bodies.append(new_body)
        new_body = CRLF.join(bodies)
        if not new_parser.is_chunk and new_body:
            try:
                (k, _) = new_parser.header_parser.headers[b'content-length']
                l = len(new_body)
                if body_type == TYPE_BODY_MULTIPART:
                    l -= 4
                new_parser.header_parser.headers[b'content-length'] = (k, str(l))
            except Exception as e:
                log.critical(b'Response is not chunked but got no Content-Length header:{0}'.format(repr(e)))
        arr.append(new_parser.header_parser.build())
        arr.append(b'')
        arr.append(new_body)
        z = CRLF.join(arr)
        return z


class HookChain(object):
    def __init__(self):
        self.hooks = []

    def add_hook(self, hook):
        self.hooks.append(hook)

    def respond_hook(self, request_parser, response_parser):
        for hook in reversed(self.hooks):
            # noinspection PyProtectedMember
            if hook._respond(request_parser, response_parser):
                return hook
        return None


class TestResponseHook(ReadWriteHook):
    def respond(self, request_parser, response_parser):
        request_header = request_parser.header_parser
        url = request_header.url or None
        hostname = url[1] if url else ''
        return 'your.hostname' == hostname

    def rewrite_server_response(self, client_parser, server_parser):
        from datetime import datetime
        server_parser.body = b'holly shit' + b''.join([str(i) for i in reversed(datetime.utcnow().utctimetuple())])
        return server_parser

    def rewrite_client_request(self, client_parser, server_parser):
        return None


HOOK_CHAIN = HookChain()

# Adding to hook chain by call HOOK_CHAIN.add_hook
# HOOK_CHAIN.add_hook(TestResponseHook())
