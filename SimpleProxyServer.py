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

from constants import TYPE_HTTP_PARSER_RESPONSE, CRLF, COLON
from hook import Context
from parser import HttpParser

log = logging.getLogger(__name__)


class IOException(Exception):
    pass


def now():
    return datetime.datetime.utcnow()


class ConnectionWrapper(object):
    """Socket connection wrapper for both server and client."""

    def __init__(self, connection_type):
        self.connection_type = connection_type
        self.connection = None
        self.closed = False
        self.buffer = b''
        self.has_hook_rebuild = False
        self.name = datetime.datetime.utcnow().isoformat('_')

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

    def flush(self, hook=None, side=None, request_parser=None, response_parser=None):
        if hook and not self.has_hook_rebuild:
            self.has_hook_rebuild = True
            try:
                new = hook.rebuild(side, request_parser, response_parser)
                self.buffer = new or self.buffer
            except Exception as e:
                log.critical('parser {0} rebuild error:{1}'.format(hook, repr(e)))

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

    def __init__(self, hostname, port, backlog, hook_chain=None):
        super(ProxyServer, self).__init__(hostname, port, backlog)
        self.hook_chain = hook_chain

    def handle(self, client):
        p = Proxy(client, self.hook_chain)
        p.daemon = True
        p.start()
        log.debug('Started process {0} to handle connection {1}'.format(p, client.connection))


class Proxy(multiprocessing.Process):
    """HTTP proxy implementation.

    Accepts connection object and act as a proxy between client and server.
    """

    def __init__(self, client, hook_chain):
        super(Proxy, self).__init__()
        self.context = Context()

        self.start_time = now()
        self.last_activity = self.start_time

        self.client = client
        self.server = None

        self.request_parser = HttpParser()
        self.response_parser = HttpParser(TYPE_HTTP_PARSER_RESPONSE)

        self.hook_chain = hook_chain

        self.connection_established_pkt = CRLF.join([
            b'HTTP/1.1 200 Connection established',
            b'Proxy-agent: SimpleProxyServer',
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
        header_parser = parser.header_parser

        # http request parser has reached the state complete, we attempt to establish connection to destination server
        if parser.finished():
            log.debug('request parser is in state complete')

            if header_parser.method == b'CONNECT':
                host, port = header_parser.url.path.split(COLON)
            elif header_parser.url:
                host, port = header_parser.url.hostname, header_parser.url.port or 80
            else:
                raise IOException('Invalid status for proxy, method {0} with no url'.format(header_parser.method))

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
            if header_parser.method == b'CONNECT':
                self.client.queue(self.connection_established_pkt)
            # for usual http requests, re-build request packet and queue for the server with appropriate headers
            else:
                self.server.queue(parser.build_request())

    def on_server_side_incoming(self, data):
        # parse incoming response packet only for non-https requests
        if not self.request_parser.header_parser.method == b'CONNECT':
            self.response_parser.parse(data)

        # queue data for client
        self.client.queue(data)

    def _access_log(self):
        request_header_parser = self.request_parser.header_parser
        response_header_parser = self.response_parser.header_parser
        host, port = self.server.address if self.server else (None, None)
        if request_header_parser.method == b'CONNECT':
            msg = '%s:%s - %s %s:%s' % (self.client.address[0], self.client.address[1], b'CONNECT', host, port)
            log.info(msg)
        elif request_header_parser.method:
            log.info('%s:%s - %s %s:%s%s - %s %s - %s bytes' % (
                self.client.address[0], self.client.address[1], request_header_parser.method, host, port,
                request_header_parser.url,
                response_header_parser.code, response_header_parser.reason, len(self.response_parser.raw)))

    def _get_waitable_lists(self):
        rlist, wlist, xlist = [self.client.connection], [], []

        if self.client.has_buffer():
            wlist.append(self.client.connection)

        if self.server and not self.server.closed:
            rlist.append(self.server.connection)

        if self.server and not self.server.closed and self.server.has_buffer():
            wlist.append(self.server.connection)

        return rlist, wlist, xlist

    def _process_writing(self, w):
        hc = self.hook_chain if self.request_parser.finished() else None
        hook = hc.respond_hook(self.request_parser, self.response_parser) if hc else None
        server_side_finished = self.response_parser.finished()
        if server_side_finished and self.client.connection in w:
            self.client.flush(hook, 0, self.request_parser, self.response_parser)

        client_side_finished = self.request_parser.finished()
        if client_side_finished and self.server and not self.server.closed and self.server.connection in w:
            self.server.flush(hook, 1, self.request_parser, self.response_parser)

    def _process_reading(self, r):
        if self.client.connection in r:
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
                    b'HTTP/1.1 502 Bad Gateway',
                    b'Proxy-agent: SimpleProxyServer',
                    b'Content-Length: 11',
                    b'Connection: close',
                    CRLF
                ]) + b'Bad Gateway')
                self.client.flush()
                return True

        if self.server and not self.server.closed and self.server.connection in r:
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
                if self.response_parser.finished():
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
    hook_chain = None
    try:
        # noinspection PyUnresolvedReferences
        from hook import HOOK_CHAIN
        hook_chain = HOOK_CHAIN
    except ImportError as e:
        log.error("can't import hooks, error:{0}".format(repr(e)))
        pass

    try:
        proxy = ProxyServer(hostname, port, 100, hook_chain=hook_chain)
        proxy.run()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
