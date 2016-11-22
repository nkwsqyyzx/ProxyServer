#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    constants.py

    A Simple HTTP Proxy Server in Python.
    :copyright: (c) 2016 by nkwsqyyzx@gmail.com
    :license: BSD, see LICENSE for more details.
"""

TYPE_PARSER_REQUEST_HEADER = 1
TYPE_PARSER_RESPONSE_HEADER = 2

TYPE_PARSER_NORMAL = 3
TYPE_PARSER_CHUNK = 4
TYPE_PARSER_MULTIPART = 5

STATE_CHUNK_PARSER_INIT = 0
STATE_CHUNK_PARSER_DATA = 1
STATE_CHUNK_PARSER_DONE = 2

TYPE_HTTP_PARSER_REQUEST = 1
TYPE_HTTP_PARSER_RESPONSE = 2

TYPE_BODY_RAW = 1
TYPE_BODY_CHUNK = 2
TYPE_BODY_MULTIPART = 3

STATE_HTTP_PARSER_INITIALIZED = 0
STATE_HTTP_PARSER_HANDLE_HEADERS = 1
STATE_HTTP_PARSER_HEADERS_DONE = 2
STATE_HTTP_PARSER_HANDLE_BODY = 3
STATE_HTTP_PARSER_DONE = 4

CRLF = b'\r\n'
SPACE = b' '
COLON = b':'
