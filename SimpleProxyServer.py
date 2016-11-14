#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    SimpleProxyServer.py

    A Simple HTTP Proxy Server in Python.
    Note:
        This project is build based on Abhinav Singh's project which hosted at https://github.com/abhinavsingh/proxy.py
        Also Abhinav Singh's project with his license file can be found at https://github.com/abhinavsingh/proxy.py
    :copyright: (c) 2016 by nkwsqyyzx@gmail.com
    :license: BSD, see LICENSE for more details.
"""
import argparse
import datetime
import logging
import multiprocessing
import select
import socket
import sys

# True if we are running on Python 3.
PY3 = sys.version_info[0] == 3

if PY3:
    from urllib import parse as urlparse
else:
    import urlparse

CRLF = '\r\n'
SPACE = ' '
COLON = ':'

log = logging.getLogger(__name__)


class IOException(Exception):
    pass


def split(content='', sub=CRLF):
    index = content.find(sub)
    return (None, content) if index < 0 else (content[:index], content[index + len(sub):])


def now():
    return datetime.datetime.utcnow()


STATE_CHUNK_PARSER_INIT = 0
STATE_CHUNK_PARSER_DATA = 1
STATE_CHUNK_PARSER_DONE = 2

TYPE_HTTP_PARSER_REQUEST = 1
TYPE_HTTP_PARSER_RESPONSE = 2

STATE_HTTP_PARSER_INITIALIZED = 0
STATE_HTTP_PARSER_HANDLE_HEADERS = 1
STATE_HTTP_PARSER_HEADERS_DONE = 2
STATE_HTTP_PARSER_HANDLE_BODY = 3
STATE_HTTP_PARSER_DONE = 4

TYPE_HOOK_CLIENT_DOWN = 1
TYPE_HOOK_SERVER_UP = 2


class ReadWriteHook(object):
    def __init__(self, hook_type):
        self.hook_type = hook_type
        # the original parser will be assigned later
        self.request_parser = None
        self.response_parser = None

    def _enable_rewrite(self):
        if self.hook_type == TYPE_HOOK_CLIENT_DOWN:
            return self._enable_rewrite_server_response(self.request_parser, self.response_parser)
        elif self.hook_type == TYPE_HOOK_SERVER_UP:
            return self._enable_rewrite_client_request(self.request_parser, self.response_parser)
        return None

    def _enable_rewrite_client_request(self, client_parser, server_parser):
        """:return self to enable hook"""
        raise NotImplementedError()

    def _enable_rewrite_server_response(self, client_parser, server_parser):
        """:return self to enable hook"""
        raise NotImplementedError()

    def rewrite_headers(self, headers):
        raise NotImplementedError()

    def rewrite_body(self, body):
        raise NotImplementedError()

    def rebuild(self):
        hook = self._enable_rewrite()
        if hook is None:
            return None

        if hook.hook_type == TYPE_HOOK_SERVER_UP:
            origin_parser = self.request_parser
        else:
            origin_parser = self.response_parser

        if origin_parser:
            arr = []
            if hook.hook_type == TYPE_HOOK_SERVER_UP:
                arr.append(SPACE.join([origin_parser.method, origin_parser.build_url(), origin_parser.version]))
            elif hook.hook_type == TYPE_HOOK_CLIENT_DOWN:
                arr.append(SPACE.join([origin_parser.version, origin_parser.code, origin_parser.reason]))
            headers = hook.rewrite_headers(origin_parser.headers)
            body = hook.rewrite_body(origin_parser.body)
            if headers is None:
                headers = origin_parser.headers

            if body is None:
                body = origin_parser.body
            else:
                if not origin_parser.is_chunk:
                    try:
                        (k, _) = headers['content-length']
                        headers['content-length'] = (k, str(len(body)))
                    except Exception as e:
                        log.critical('Response is not chunked but got no Content-Length header:{0}'.format(repr(e)))

            for k in headers or {}:
                arr.append(headers[k][0] + COLON + SPACE + headers[k][1])
            if body:
                if origin_parser.is_chunk:
                    arr.append('')
                    arr.append(hex(len(body))[2:])
                    arr.append(body)
                    arr.append('0')
                    arr.append(CRLF)
                else:
                    arr.append('')
                    arr.append(body)

            return CRLF.join(arr)
        else:
            log.critical('hook has been enabled but got wrong type of parser')
        return None


class ChunkParser(object):
    """Chunked encoding response parser."""

    def __init__(self):
        self.state = STATE_CHUNK_PARSER_INIT
        self.body = ''
        self.chunk = ''
        self.size = 0

    def parse(self, data):
        more = len(data) > 0
        while more:
            more, data = self.process(data)

    def process(self, data):
        if self.state == STATE_CHUNK_PARSER_INIT:
            size, data = split(data)
            # read chunk size
            self.size = int(size, 16) if size else 0
            self.state = STATE_CHUNK_PARSER_DATA
        elif self.state == STATE_CHUNK_PARSER_DATA:
            remaining = self.size - len(self.chunk)
            self.chunk += data[:remaining]
            data = data[remaining:]
            if len(self.chunk) == self.size:
                data = data[len(CRLF):]
                self.body += self.chunk
                self.state = STATE_CHUNK_PARSER_INIT if self.size > 0 else STATE_CHUNK_PARSER_DONE
                self.chunk = ''
                self.size = 0
        elif self.state == STATE_CHUNK_PARSER_DONE:
            pass
        else:
            raise IOException('Unexpected state {0}'.format(self.state))
        return len(data) > 0, data


class ConnectionWrapper(object):
    """Socket connection wrapper for both server and client."""

    def __init__(self, connection_type):
        self.connection_type = connection_type
        self.connection = None
        self.closed = False
        self.buffer = ''
        self.has_hook_rebuild = False

    def receive(self, size=8192):
        try:
            data = self.connection.recv(size)
            log.debug('got {0} bytes from {1}'.format(len(data), self.connection_type))
            return data
        except Exception as e:
            raise IOException(e)

    def buffer_size(self):
        return len(self.buffer)

    def has_buffer(self):
        return self.buffer_size() > 0

    def close(self):
        self.connection.close()
        self.closed = True

    def queue(self, data):
        self.buffer += data

    def flush(self, parser=None):
        if parser and parser.hook and not self.has_hook_rebuild:
            self.has_hook_rebuild = True
            self.buffer = parser.hook.rebuild() or self.buffer

        sent = self.connection.send(self.buffer)
        self.buffer = self.buffer[sent:]
        log.debug('flushed {0} bytes to {1}'.format(sent, self.connection_type))


class Server(ConnectionWrapper):
    """Proxy connection bind to destination server."""

    def __init__(self, host, port):
        super(Server, self).__init__('server({0}, {1})'.format(host, port))
        self.address = (host, int(port))

    def connect(self):
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connection.connect((self.address[0], self.address[1]))


class Client(ConnectionWrapper):
    """Proxy connection bind to the client."""

    def __init__(self, connection, address):
        super(Client, self).__init__('client{0}'.format(address))
        self.connection = connection
        self.address = address


class TCPServer(object):
    """TCP server implementation."""

    def __init__(self, hostname, port, backlog):
        self.hostname = hostname
        self.port = port
        self.backlog = backlog

    def handle(self, client):
        raise NotImplementedError()

    def run(self):
        log.info('Starting server on ({0}, {1})'.format(self.hostname, self.port))
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.hostname, self.port))
            sock.listen(self.backlog)
            while True:
                connection, address = sock.accept()
                log.debug('Incoming connection from {0}'.format(address))
                self.handle(Client(connection, address))
        except Exception as e:
            log.exception('Exception while running the server {0}'.format(repr(e)))
        finally:
            log.info('Closing server on ({0}, {1})'.format(self.hostname, self.port))
            if sock:
                sock.close()


class ProxyServer(TCPServer):
    """Proxy server implemented with multi processing"""

    def __init__(self, hostname, port, backlog, client_hook=None, server_hook=None):
        super(ProxyServer, self).__init__(hostname, port, backlog)
        self.client_hook = client_hook
        self.server_hook = server_hook

    def handle(self, client):
        p = Proxy(client, self.client_hook, self.server_hook)
        p.daemon = True
        p.start()
        log.debug('Started process {0} to handle connection {1}'.format(p, client.connection))


class Proxy(multiprocessing.Process):
    """HTTP proxy implementation.

    Accepts connection object and act as a proxy between client and server.
    """

    def __init__(self, client, client_hook, server_hook):
        super(Proxy, self).__init__()

        self.start_time = now()
        self.last_activity = self.start_time

        self.client = client
        self.server = None

        self.request_parser = HttpParser(hook=server_hook)
        self.response_parser = HttpParser(TYPE_HTTP_PARSER_RESPONSE, hook=client_hook)

        hooks = []

        if client_hook:
            hooks.append(client_hook)
        if server_hook:
            hooks.append(server_hook)
        for hook in hooks:
            hook.request_parser = self.request_parser
            hook.response_parser = self.response_parser

        self.connection_established_pkt = CRLF.join([
            'HTTP/1.1 200 Connection established',
            'Proxy-agent: SimpleProxyServer',
            CRLF
        ])

    def _inactive_for(self):
        return (now() - self.last_activity).seconds

    def _is_inactive(self):
        return self._inactive_for() > 120

    def on_client_side_incoming(self, data):
        # server connection is ready, just buffer data
        if self.server and not self.server.closed:
            self.server.queue(data)
            return

        parser = self.request_parser

        # server connection is not ready, parse data and connect to server
        parser.parse(data)

        # http request parser has reached the state complete, we attempt to establish connection to destination server
        if parser.state == STATE_HTTP_PARSER_DONE:
            log.debug('request parser is in state complete')

            if parser.method == 'CONNECT':
                host, port = parser.url.path.split(COLON)
            elif parser.url:
                host, port = parser.url.hostname, parser.url.port or 80
            else:
                raise IOException('Invalid status for proxy, method {0} with no url'.format(parser.method))

            self.server = Server(host, port)
            try:
                log.debug('connecting to server ({0}, {1})'.format(host, port))
                self.server.connect()
                log.debug('connected to server ({0}, {1})'.format(host, port))
            except Exception as e:
                self.server.closed = True
                raise IOException(host, port, repr(e))

            # for http connect methods (https requests) queue appropriate response for client
            # and also notifying about established connection
            if parser.method == 'CONNECT':
                self.client.queue(self.connection_established_pkt)
            # for usual http requests, re-build request packet and queue for the server with appropriate headers
            else:
                del_headers = ['proxy-connection', 'connection', 'keep-alive']
                add_headers = [('Connection', 'Close')]
                self.server.queue(parser.build_request(del_headers=del_headers, add_headers=add_headers))

    def on_server_side_incoming(self, data):
        # parse incoming response packet only for non-https requests
        if not self.request_parser.method == 'CONNECT':
            self.response_parser.parse(data)

        # queue data for client
        self.client.queue(data)

    def _access_log(self):
        parser = self.request_parser
        host, port = self.server.address if self.server else (None, None)
        if parser.method == 'CONNECT':
            msg = '%s:%s - %s %s:%s' % (self.client.address[0], self.client.address[1], parser.method, host, port)
            log.info(msg)
        elif parser.method:
            log.info('%s:%s - %s %s:%s%s - %s %s - %s bytes' % (
                self.client.address[0], self.client.address[1], parser.method, host, port,
                parser.build_url(),
                self.response_parser.code, self.response_parser.reason, len(self.response_parser.raw)))

    def _get_waitable_lists(self):
        rlist, wlist, xlist = [self.client.connection], [], []
        log.debug('*** watching client for read ready')

        if self.client.has_buffer():
            log.debug('pending client buffer found, watching client for write ready')
            wlist.append(self.client.connection)

        if self.server and not self.server.closed:
            log.debug('connection to server exists, watching server for read ready')
            rlist.append(self.server.connection)

        if self.server and not self.server.closed and self.server.has_buffer():
            log.debug('connection to server exists and pending server buffer found, watching server for write ready')
            wlist.append(self.server.connection)

        return rlist, wlist, xlist

    def _process_writing(self, w):
        server_side_finished = self.response_parser.finished()
        if server_side_finished and self.client.connection in w:
            log.debug('client is ready for writes, flushing client buffer')
            self.client.flush(self.response_parser)

        client_side_finished = self.request_parser.finished()
        if client_side_finished and self.server and not self.server.closed and self.server.connection in w:
            log.debug('server is ready for writes, flushing server buffer')
            self.server.flush(self.request_parser)

    def _process_reading(self, r):
        if self.client.connection in r:
            log.debug('client is ready for reads, reading')
            data = self.client.receive()
            self.last_activity = now()

            if not data:
                log.debug('client closed connection, breaking')
                return True

            try:
                self.on_client_side_incoming(data)
            except IOException as e:
                log.exception(e)
                self.client.queue(CRLF.join([
                    'HTTP/1.1 502 Bad Gateway',
                    'Proxy-agent: SimpleProxyServer',
                    'Content-Length: 11',
                    'Connection: close',
                    CRLF
                ]) + 'Bad Gateway')
                self.client.flush()
                return True

        if self.server and not self.server.closed and self.server.connection in r:
            log.debug('server is ready for reads, reading')
            data = self.server.receive()
            self.last_activity = now()

            if not data:
                log.debug('server closed connection')
                self.server.close()
            else:
                self.on_server_side_incoming(data)

        return False

    def _process(self):
        while True:
            rlist, wlist, xlist = self._get_waitable_lists()
            r, w, x = select.select(rlist, wlist, xlist, 1)

            self._process_writing(w)
            if self._process_reading(r):
                break

            if self.client.buffer_size() == 0:
                if self.response_parser.state == STATE_HTTP_PARSER_DONE:
                    log.debug('client buffer is empty and response state is complete, breaking')
                    break

                if self._is_inactive():
                    log.debug('client buffer is empty and maximum inactivity has reached, breaking')
                    break

    def run(self):
        log.debug('Proxying connection initialized at address {0}'.format(self.client.address))
        try:
            self._process()
        except KeyboardInterrupt:
            pass
        except Exception as e:
            log.exception('Exception while handling connection %r with reason %r' % (self.client.connection, e))
        finally:
            log.debug(
                'closing client connection with pending client buffer size %d bytes' % self.client.buffer_size())
            self.client.close()
            if self.server:
                log.debug(
                    'closed client connection with pending server buffer size %d bytes' % self.server.buffer_size())
            self._access_log()
            log.debug(
                'Closing proxy for connection %r at address %r' % (self.client.connection, self.client.address))


class HttpParser(object):
    """HTTP request/response parser."""

    def __init__(self, parser_type=TYPE_HTTP_PARSER_REQUEST, hook=None):
        self.state = STATE_HTTP_PARSER_INITIALIZED
        self.parser_type = parser_type

        self.raw = ''
        self.buffer = ''

        self.headers = dict()
        self.body = None

        self.method = None
        self.url = None
        self.code = None
        self.reason = None
        self.version = None

        self.chunk_parser = ChunkParser()
        self.is_chunk = False
        self.hook = hook

    def parse(self, data):
        self.raw += data
        data = self.buffer + data
        self.buffer = ''

        more = True if len(data) > 0 else False
        while more:
            more, data = self.process(data)
        self.buffer = data

    def _post_or_response(self):
        return self.method == 'POST' or self.parser_type == TYPE_HTTP_PARSER_RESPONSE

    def _get_and_request(self):
        return not self.method == 'POST' and self.parser_type == TYPE_HTTP_PARSER_REQUEST

    def process(self, data):
        if self.state >= STATE_HTTP_PARSER_HEADERS_DONE and self._post_or_response():
            if not self.body:
                self.body = ''

            if 'content-length' in self.headers:
                self.state = STATE_HTTP_PARSER_HANDLE_BODY
                self.body += data
                if len(self.body) >= int(self.headers['content-length'][1]):
                    self.state = STATE_HTTP_PARSER_DONE
            elif 'transfer-encoding' in self.headers and self.headers['transfer-encoding'][1].lower() == 'chunked':
                self.is_chunk = True
                self.chunk_parser.parse(data)
                if self.chunk_parser.state == STATE_CHUNK_PARSER_DONE:
                    self.body = self.chunk_parser.body
                    self.state = STATE_HTTP_PARSER_DONE

            return False, ''

        line, data = split(data)
        if line is None:
            return line, data

        if self.state == STATE_HTTP_PARSER_INITIALIZED:
            self.parse_method(line)
        elif self.state < STATE_HTTP_PARSER_HEADERS_DONE:
            self.parse_header(line)

        if self.state == STATE_HTTP_PARSER_HEADERS_DONE and self._get_and_request() and self.raw.endswith(CRLF * 2):
            self.state = STATE_HTTP_PARSER_DONE

        return len(data) > 0, data

    def finished(self):
        return self.parser_type != self.hook.hook_type or self.state == STATE_HTTP_PARSER_DONE

    def parse_method(self, data):
        """Parse http method from content."""
        # read first line
        line = data.split(SPACE)
        if self.parser_type == TYPE_HTTP_PARSER_REQUEST:
            self.method = line[0].upper()
            self.url = urlparse.urlsplit(line[1])
            self.version = line[2]
        else:
            self.version = line[0]
            self.code = line[1]
            self.reason = ' '.join(line[2:])
        self.state = STATE_HTTP_PARSER_HANDLE_HEADERS

    def parse_header(self, data):
        if len(data) == 0:
            if self.state == STATE_HTTP_PARSER_HANDLE_HEADERS:
                self.state = STATE_HTTP_PARSER_HEADERS_DONE
        else:
            self.state = STATE_HTTP_PARSER_HANDLE_HEADERS
            parts = data.split(COLON)
            key = parts[0].strip()
            value = COLON.join(parts[1:]).strip()
            self.headers[key.lower()] = (key, value)

    def build_url(self):
        if not self.url:
            return '/None'

        url = self.url.path
        if url == '':
            url = '/'
        if not self.url.query == '':
            url += '?' + self.url.query
        if not self.url.fragment == '':
            url += '#' + self.url.fragment
        return url

    def build_request(self, del_headers=None, add_headers=None):
        arr = [' '.join([self.method, self.build_url(), self.version])]

        for k in self.headers:
            if k not in del_headers or []:
                arr.append(self.headers[k][0] + COLON + SPACE + self.headers[k][1])

        for k in add_headers or []:
            arr.append(k[0] + COLON + SPACE + k[1])

        arr.append(CRLF)
        if self.body:
            arr.append(self.body)

        return CRLF.join(arr)


def main():
    parser = argparse.ArgumentParser(
        description='SimpleProxyServer.py',
    )

    parser.add_argument('--hostname', default='127.0.0.1', help='Default: 127.0.0.1')
    parser.add_argument('--port', default='8899', help='Default: 8899')
    parser.add_argument('--log-level', default='DEBUG', help='DEBUG, INFO, WARNING, ERROR, CRITICAL')
    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, args.log_level),
                        format='%(asctime)s - %(levelname)s - pid:%(process)d - %(message)s')

    hostname = args.hostname
    port = int(args.port)
    client_hook = None
    server_hook = None
    try:
        # noinspection PyUnresolvedReferences
        from hook import CLIENT_HOOK, SERVER_HOOK
        client_hook = CLIENT_HOOK
        server_hook = SERVER_HOOK
    except ImportError as e:
        log.error("can't import hooks, hooks not found:{0}".format(repr(e)))
        pass

    try:
        proxy = ProxyServer(hostname, port, 100, client_hook, server_hook)
        proxy.run()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
