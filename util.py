#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    util.py

    A Simple HTTP Proxy Server in Python.
    :copyright: (c) 2016 by nkwsqyyzx@gmail.com
    :license: BSD, see LICENSE for more details.
"""

import json

from google.protobuf import descriptor

_TYPE_DOUBLE = 1
_TYPE_FLOAT = 2
_TYPE_INT64 = 3
_TYPE_UINT64 = 4
_TYPE_INT32 = 5
_TYPE_FIXED64 = 6
_TYPE_FIXED32 = 7
_TYPE_BOOL = 8
_TYPE_STRING = 9
_TYPE_GROUP = 10
_TYPE_MESSAGE = 11
_TYPE_BYTES = 12
_TYPE_UINT32 = 13
_TYPE_ENUM = 14
_TYPE_SFIXED32 = 15
_TYPE_SFIXED64 = 16
_TYPE_SINT32 = 17
_TYPE_SINT64 = 18

_INT_TYPE = [_TYPE_INT64, _TYPE_UINT64, _TYPE_INT32, _TYPE_FIXED64, _TYPE_FIXED32, _TYPE_UINT32, _TYPE_ENUM,
             _TYPE_SFIXED32, _TYPE_SFIXED64, _TYPE_SINT32, _TYPE_SINT64, ]


def json_proto(root, msg):
    if root is None or (not msg):
        return
    name_type = [(i.name, i.label, i.type) for i in root.DESCRIPTOR.fields]
    for (name, label, msg_type) in name_type:
        if label == descriptor.FieldDescriptor.LABEL_REPEATED:
            arr = getattr(root, name)
            for i in msg.get(name, []):
                new = arr.add()
                json_proto(new, i)
            continue
        if msg_type == _TYPE_MESSAGE:
            json_proto(getattr(root, name), msg.get(name))
        elif msg_type in [_TYPE_DOUBLE, _TYPE_FLOAT]:
            setattr(root, name, float(msg.get(name) or '0'))
        elif msg_type in _INT_TYPE:
            v = msg.get(name)
            try:
                setattr(root, name, int(v or 0))
            except ValueError as e:
                x = int(v) & 0x7FFFFFFF
                print '{0}, reset to {1}'.format(e.message, x)
                setattr(root, name, x)
        elif msg_type == _TYPE_STRING:
            sz = msg.get(name, u'')
            try:
                setattr(root, name, sz.encode('utf8'))
            except Exception as e:
                sz = str(sz)
                setattr(root, name, sz.encode('utf8'))
                print '{0}, reset to {1}'.format(e.message, sz)
        else:
            raise Exception('Unknown message type {0} for field {1}'.format(msg_type, name))
