#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    parser.py

    Parser for http request/response.
    :copyright: (c) 2016 by nkwsqyyzx@gmail.com
    :license: BSD, see LICENSE for more details.
"""
import StringIO
import cgi
import logging
import sys

from multipart import MultipartParser as _MultipartParser

from constants import *
from hook import Context

# True if we are running on Python 3.
PY3 = sys.version_info[0] == 3

if PY3:
    from urllib import parse as urlparse
else:
    import urlparse

log = logging.getLogger(__name__)


def split(content=b'', sub=CRLF):
    index = content.find(sub)
    return (None, content) if index < 0 else (content[:index], content[index + len(sub):])


class _Parser(object):
    def __init__(self, parser_type):
        self._state = 0
        self.parser_type = parser_type
        self.raw = b''
        self.is_done = False
        self.rebuild_body = b''

    def feed(self, raw):
        self.raw += raw
        self._on_data_coming(raw)

    def _on_data_coming(self, raw):
        raise NotImplementedError()

    @property
    def body(self):
        raise NotImplementedError()

    def build(self):
        raise NotImplementedError()


class ChunkParser(_Parser):
    def __init__(self):
        super(ChunkParser, self).__init__(TYPE_PARSER_CHUNK)
        self._size = 0
        self._current_part = b''
        self.parts = []

    def _on_data_coming(self, raw):
        self._parse_chunk(raw)

    def _parse_chunk(self, raw):
        if len(raw) == 0:
            return
        if self.is_done:
            log.critical("chunk parser is finished, but still got {0} bytes to parse".format(len(raw)))
            return
        # content part:hex(len(buffer))_CRLF_buffer_CRLF
        # ending part:0_CRLF_CRLF
        if self._state == 0:
            self._current_part = b''
            # read size first, then parse body
            size, remain = split(raw)
            # read chunk size
            self._size = int(size, 16) if size else 0
            self._state = 1 if self._size > 0 else 2
            # recursive call to parse real body
            self._parse_chunk(remain)
        elif self._state == 1:
            waiting = self._size - len(self._current_part)
            if waiting > 0:
                self._current_part += raw[:waiting]
                remain = raw[waiting:]
            else:
                self._current_part = raw[:self._size]
                remain = raw[self._size + len(CRLF):]
            if len(self._current_part) == self._size:
                # current part finished
                self.parts.append(self._current_part)
                self._state = 0
                # because current part is done, remaining buffer should remove first leading CRLF
                remain = remain[len(CRLF):]
            if len(remain) > 0:
                self._parse_chunk(remain)
        elif self._state == 2:
            self.is_done = True
        else:
            log.critical("chunk parser got invalid state {0}".format(self._state))

    @property
    def body(self):
        if not self.is_done:
            log.warning("try to access body when chunk parser is not finished")
        return self.rebuild_body or b''.join(self.parts)

    def build(self):
        raise Exception("TODO")


class MultipartParser(object):
    """Multipart form-data parser"""

    def __init__(self):
        self.boundary = b''
        self.body = dict()
        self.names = []
        self.rebuild_body = dict()

    def parse(self, body, v):
        raw = body
        self.boundary = v[b'boundary']
        fp = StringIO.StringIO(body)
        parts = _MultipartParser(fp, self.boundary).parts()
        fp.seek(0)
        body = cgi.parse_multipart(fp, v)
        self.body.clear()
        for p in parts:
            b = b''.join(body[p.name])
            v = p
            self.body[p.name] = (b, v)

        self.names = []
        parts = [s.strip() for s in raw.split(self.boundary) if b'Content-Disposition' in s]
        for p in parts:
            ps = p.split('"')
            if len(ps) > 1:
                n = ps[1]
                self.names.append(n)

    def raw_body(self, key):
        kv = self.body[key]
        return kv[0] if kv else ''


class HeaderParser(_Parser):
    def __init__(self, parser_type):
        super(HeaderParser, self).__init__(parser_type)
        self._index = 0
        self._cached_boundary = None
        self._has_cached_boundary = False
        self.header_names = []
        self.headers = dict()

        self.method = None
        self.url = None
        self.code = None
        self.reason = None
        self.version = None

    def _parse_first_line(self, data):
        line = data.split(SPACE)
        if len(line) < 3:
            # still request more data to parse first line
            return
        if self.parser_type == TYPE_PARSER_REQUEST_HEADER:
            self.method = line[0].upper()
            self.url = urlparse.urlsplit(line[1])
            self.version = line[2]
        else:
            self.version = line[0]
            self.code = line[1]
            self.reason = b' '.join(line[2:])
        self._state = 1
        self._index += len(data) + len(CRLF)

    def _on_data_coming(self, raw):
        if len(raw) == 0 or self.is_done:
            return
        self._parse_header()

    def _parse_header(self):
        raw = self.raw[self._index:]
        if self._state == 0:
            line, _ = split(raw)
            self._parse_first_line(line)
            self._parse_header()
        elif self._state == 1:
            line, _ = split(raw)
            if line is None or len(line) == 0:
                if raw.startswith(CRLF):
                    self._state = 2
                    self.raw = self.raw[0:self._index + len(CRLF)]
                    self.is_done = True
                # still request more data to parse current header
                return
            self._index += len(line) + len(CRLF)
            name, value = split(line, COLON)
            if name and name.strip():
                key = name.strip()
                value = value.strip()
                self.header_names.append(key.lower())
                self.headers[key.lower()] = (key, value)
            else:
                log.critical("invalid header line ({0})".format(line))
            self._parse_header()
        elif self._state == 2:
            self.is_done = True
            return
        else:
            log.critical("chunk parser got invalid state {0}".format(self._state))

    def value(self, key):
        """
        key will be treated as lower case
        :param key:
        :return:
        """
        (_, v) = self.headers.get(key.lower()) or ('', '')
        return v

    def has_header(self, key):
        return self.headers.__contains__(key)

    def boundary(self):
        if self._has_cached_boundary:
            return self._cached_boundary
        v = self.value(b'content-type')
        if v:
            k, v = cgi.parse_header(v)
            self._has_cached_boundary = True
            self._cached_boundary = v if k == b'multipart/form-data' else None
        return self._cached_boundary

    def build(self):
        url = self.url or None
        u = url.path if url else ''
        if url:
            if u == b'':
                u = b'/'
            if not url.query == b'':
                u += b'?' + url.query
            if not url.fragment == b'':
                u += b'#' + url.fragment

        if self.parser_type == TYPE_PARSER_REQUEST_HEADER:
            first_line = b' '.join([self.method, u, self.version])
        else:
            first_line = b' '.join([self.version, self.code, self.reason])
        arr = [first_line]

        del_headers = [b'proxy-connection', b'connection', b'keep-alive']
        add_headers = [(b'Connection', b'Close')]

        for k in self.header_names:
            if k not in del_headers or []:
                k, v = self.headers[k]
                arr.append(k + COLON + SPACE + v)
        for (k, v) in add_headers or []:
            arr.append(k + COLON + SPACE + v)
        return CRLF.join(arr)

    @property
    def body(self):
        raise Exception("invalid call for header parser")

    @staticmethod
    def create_parser(is_request):
        return HeaderParser(TYPE_PARSER_REQUEST_HEADER if is_request else TYPE_PARSER_RESPONSE_HEADER)


class HttpParser(object):
    """HTTP request/response parser."""

    def __init__(self, parser_type=TYPE_HTTP_PARSER_REQUEST):
        self.context = Context()
        self._state = STATE_HTTP_PARSER_INITIALIZED
        self.parser_type = parser_type
        self.body_type = TYPE_BODY_RAW

        self.raw = b''

        self.header_parser = HeaderParser.create_parser(parser_type == TYPE_HTTP_PARSER_REQUEST)
        self.body = b''
        self.rebuild_body = b''

        self.is_multipart = False
        self.multipart_parser = MultipartParser()

        self.chunk_parser = ChunkParser()
        self.is_chunk = False
        self._block_guard = 0

        self.content_length = -1

    @property
    def type_body(self):
        if self.is_multipart:
            body = self.multipart_parser.rebuild_body or self.multipart_parser.body
        else:
            target = self.chunk_parser if self.is_chunk else self
            body = target.rebuild_body or target.body
        return self.body_type, body

    @property
    def raw_body(self):
        target = self.multipart_parser if self.is_multipart else (self.chunk_parser if self.is_chunk else self)
        return self.body_type, target.body

    @type_body.setter
    def type_body(self, rebuild_body):
        if self.is_multipart:
            self.multipart_parser.rebuild_body = rebuild_body
        else:
            if self.is_chunk:
                self.chunk_parser.rebuild_body = rebuild_body
            else:
                self.rebuild_body = rebuild_body

    def parse(self, data):
        self.raw += data
        more = True if len(data) > 0 else False
        new_data = data
        while more:
            more, new_data = self.process(new_data)
            if len(new_data) == len(data):
                log.critical("not moving forward for {0} times".format(self._block_guard))
                self._block_guard += 1
            else:
                self._block_guard = 0
            if self._block_guard >= 10:
                break

        if self.header_parser.is_done and self._get_and_request():
            self._state = STATE_HTTP_PARSER_DONE

    def _post_or_response(self):
        return self.header_parser.method == b'POST' or self.parser_type == TYPE_HTTP_PARSER_RESPONSE

    def _get_and_request(self):
        return not self.header_parser.method == b'POST' and self.parser_type == TYPE_HTTP_PARSER_REQUEST

    def process(self, data):
        if self.header_parser.is_done and self._post_or_response():
            content_length = self.header_parser.value(b'Content-Length')
            if content_length:
                self._state = STATE_HTTP_PARSER_HANDLE_BODY
                self.body += data
                self.content_length = int(content_length)
                log.debug('content_length:{0}, current length {1}'.format(self.content_length, len(self.body)))
                if len(self.body) >= self.content_length:
                    self._state = STATE_HTTP_PARSER_DONE
                    v = self.header_parser.boundary()
                    if v:
                        self.is_multipart = True
                        self.multipart_parser.parse(self.body, v)
                        self.body_type = TYPE_BODY_MULTIPART
            else:
                value = self.header_parser.value(b'Transfer-Encoding')
                if value.lower() == b'chunked':
                    self.is_chunk = True
                    self.body_type = TYPE_BODY_CHUNK
                    self.chunk_parser.feed(data)
                    if self.chunk_parser.is_done:
                        self.body = self.chunk_parser.body
                        self._state = STATE_HTTP_PARSER_DONE
                else:
                    # normal body
                    self.body += data

            return False, b''

        if not self.header_parser.is_done:
            self.header_parser.feed(data)
            should_truncate_headers = self.header_parser.is_done
        else:
            should_truncate_headers = True

        data = self.raw[(len(self.header_parser.raw) if should_truncate_headers else 0):]
        return len(data) > 0, data

    def finished(self):
        return self.chunk_parser.is_done if self.is_chunk else self._state == STATE_HTTP_PARSER_DONE

    def build_request(self):
        arr = [self.header_parser.build(), CRLF]

        if self.body:
            arr.append(self.body)

        return CRLF.join(arr)
