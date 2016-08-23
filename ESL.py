# -*- coding: utf-8 -*-

# Copyright (c) 2016 Spencer Thomason
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""
Event Socket Client
"""


from __future__ import unicode_literals
import socket
from sys import version_info

try:
    from urllib.parse import quote, unquote
except (ImportError):
    from urllib import quote, unquote

try:
    string_types = basestring
except (NameError):
    string_types = str


def to_bytes(s):
    if isinstance(s, bytes):
        return s

    if version_info >= (3, 0, 0):
        return bytes(s, 'utf-8')

    return bytes(s)


class ESLevent(object):

    def __init__(self, event_type, event_subclass=None):
        self.__body = None
        self.__header_names = []
        self.__header_names_upper = []
        self.__header_values = []
        self.__header_idx = 0
        self.addHeader("Event-Name", event_type)
        if event_subclass is not None:
            self.addHeader("Event-Subclass", event_subclass)

    def serialize(self, ser_format="plain"):
        """
        Serializes event object in either plain or JSON format
        """

        event_data = []
        header = self.firstHeader()
        while header:
            val = self.getHeader(header)
            event_data.append((header, val))
            header = self.nextHeader()
        body = self.getBody()
        if body:
            event_data.append(('Content-Length', str(len(body))))
            event_data.append(('_body', body))

        ser = []
        if ser_format == 'json':
            for header in event_data:
                if isinstance(header[1], list):
                    json_val = []
                    for val in header[1]:
                        json_val.append('"%s"' % (val))
                    json_val = '[%s]' % (', '.join(json_val))
                else:
                    json_val = '"%s"' % (header[1])
                ser.append('\t"%s":\t%s' % (header[0], json_val))
            return '{\n%s\n}' % (',\n'.join(ser))
        else:
            for header in event_data:
                if header[0] == '_body':
                    ser.append('\n%s' % (header[1]))
                else:
                    if isinstance(header[1], list):
                        if len(header[1]) > 1:
                            val = "ARRAY::%s" % ('|:'.join(header[1]))
                        else:
                            val = header[1][0]
                    else:
                        val = header[1]
                    ser.append('%s: %s' % (header[0], quote(val)))
            return '%s\n\n' % ('\n'.join(ser))

    def setPriority(self, *args, **kwargs):
        raise(NotImplementedError)

    def getHeader(self, header_name):
        """
        returns the header with key of `header_name` from the event object
        """

        try:
            idx = self.__header_names_upper.index(header_name.upper())
        except (ValueError):
            return
        return self.__header_values[idx]

    def getBody(self, *args):
        """
        returns the body of the event object
        """
        return self.__body

    def getType(self, *args):
        """
        returns the event type of an event object.
        """

        event_name = self.getHeader('Event-Name')
        if event_name:
            return event_name
        else:
            return 'COMMAND'

    def addBody(self, value):
        """
        Add `value` to the body of an event object.
        This can be called multiple times for the same event object.
        """
        if value is None:
            value = ''
        elif isinstance(value, bytes):
            value = value.decode("utf-8")

        if self.__body is None:
            self.__body = value
        else:
            self.__body = ''.join([self.__body, value])
        return True

    def addHeader(self, header_name, value):
        self._add_header_string(header_name, value)
        return True

    def pushHeader(self, header_name, value):
        self._add_header_array(header_name, value)
        return True

    def unshiftHeader(self, header_name, value):
        self._add_header_array(header_name, value, top=True)
        return True

    def delHeader(self, header_name):
        try:
            idx = self.__header_names_upper.index(header_name.upper())
        except (ValueError):
            return
        self.__header_names.pop(idx)
        self.__header_names_upper.pop(idx)
        self.__header_values.pop(idx)

    def firstHeader(self):
        self.__header_idx = 0
        try:
            return self.__header_names[self.__header_idx]
        except(IndexError):
            return

    def nextHeader(self):
        idx = self.__header_idx + 1
        try:
            header_name = self.__header_names[idx]
        except(IndexError):
            return
        self.__header_idx = idx
        return header_name

    def _add_header_string(self, hname, hval, top=False):

        # make header name matching sane
        if isinstance(hname, bytes):
            hname = hname.decode("utf-8")

        if not isinstance(hval, string_types):
            hval = str(hval)

        if top:
            self.__header_names.insert(0, hname)
            self.__header_names_upper.insert(0, hname.upper())
            self.__header_values.insert(0, hval)
        else:
            self.__header_names.append(hname)
            self.__header_names_upper.append(hname.upper())
            self.__header_values.append(hval)
        return

    def _add_header_array(self, hname, hval, top=False):

        # get existing header index
        idx = None
        try:
            idx = self.__header_names_upper.index(hname.upper())
        except (ValueError):
            pass

        if isinstance(hval, list):
            if idx is not None:
                self.__header_values[idx] = hval
            else:
                if top:
                    self.__header_names.insert(0, hname)
                    self.__header_names_upper.insert(0, hname.upper())
                    self.__header_values.insert(0, hval)
                else:
                    self.__header_names.append(hname)
                    self.__header_names_upper.append(hname.upper())
                    self.__header_values.append(hval)
            return

        # ensure we are dealing with strings
        if not isinstance(hval, string_types):
            hval = str(hval)

        if hval[:7] == "ARRAY::":
            hval = hval[7:].split('|:')

        if idx is not None:
            self.__header_values[idx].append(hval)
        else:
            if top:
                self.__header_names.insert(0, hname)
                self.__header_names_upper.insert(0, hname.upper())
                self.__header_values.insert(0, [hval])
            else:
                self.__header_names.append(hname)
                self.__header_names_upper.append(hname.upper())
                self.__header_values.append([hval])
        return


class ESLconnection(object):

    __async_execute = False
    __connected = False
    __event_lock = False

    def __init__(self, host, port, password):
        self.__event_queue = []

        try:
            self.__sock = socket.create_connection((host, int(port)), timeout=2)
        except (socket.error):
            self.__connected = False
            self.__sock = None
            return

        self.__sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.__connected = True

        # get the initial header
        event = self.recvEvent()

        # did we get the request for auth?
        if event.getHeader('Content-Type') != "auth/request":
            raise RuntimeError("unexpected header recieved during authentication")
        del event

        # send our auth
        event = self.sendRecv("auth %s" % (password))

        # was our auth accepted?
        reply = event.getHeader('Reply-Text')
        if reply != "+OK accepted":
            self.__connected = False
            raise RuntimeError("connection refused: %s" % (reply))

    def api(self, command, args=None):
        if not self.connected():
            return

        if args:
            command = "api %s %s" % (command, args)
        else:
            command = "api %s" % (command)
        return self.sendRecv(command)

    def bgapi(self, command, args=None, job_uuid=None):
        if not self.connected():
            return

        if args:
            command = "bgapi %s %s" % (command, args)
        else:
            command = "bgapi %s" % (command)

        if job_uuid:
            command = "%s\nJob-UUID: %s" (command, job_uuid)

        return self.sendRecv(command)

    def connected(self):
        if self.__sock and self.__connected:
            return 1
        return 0

    def disconnect(self):
        if self.__sock:
            self.__sock.shutdown(socket.SHUT_RDWR)
            self.__sock.close()
            self.__sock = None
            self.__connected = False
        return 0

    def events(self, etype, value):
        if etype != "xml" or etype != "json":
            etype = "plain"
        command = "event %s %s" % (etype, value)
        self.sendRecv(command)
        return 0

    def execute(self, app, arg=None, uuid=None, force_async=False):
        if not self.connected():
            return

        command = []
        if uuid is not None:
            command.append("sendmsg %s" % (uuid))
        else:
            command.append("sendmsg")
        command.append("call-command: execute")
        command.append("execute-app-name: %s" % (app))
        if arg is not None:
            command.append("execute-app-arg: %s" % (arg))
        if self.__event_lock:
            command.append("event-lock: true")
        if self.__async_execute or force_async:
            command.append("async: true")
        command = '\n'.join(command)
        return self.sendRecv(command)

    def executeAsync(self, app, arg=None, uuid=None):
        return self.execute(app, arg, uuid, force_async=True)

    def filter(self, header, value):
        command = "filter %s %s"
        return self.sendRecv(command)

    def getInfo(self, *args, **kwargs):
        raise(NotImplementedError)

    def recvEvent(self):
        return self.recvEventTimed()

    def recvEventTimed(self, ms=None):
        if not self.connected():
            return ESLevent("SERVER_DISCONNECTED")

        if len(self.__event_queue) > 0:
            return self.__event_queue.pop(0)

        orig_timeout = self.__sock.gettimeout()
        if ms is not None:
            if ms < 1:
                ms = 1
            timeout = float(ms) / 1000
        else:
            timeout = None
        self.__sock.settimeout(timeout)

        try:
            data = self.__receive()
        except(socket.timeout):
            data = None

        self.__sock.settimeout(orig_timeout)

        if data:
            event = ESLevent("SOCKET_DATA")
            data = data.split('\n\n')
            headers = data.pop(0)
            data = '\n\n'.join(data)

            for line in headers.splitlines():
                hname, hval = (None, None)
                try:
                    hname, hval = line.split(': ')
                except (ValueError):
                    continue
                if hname and hval:
                    hval = unquote(hval)
                    if hval[:7] == "ARRAY::":
                        event._add_header_array(hname, hval)
                    else:
                        event._add_header_string(hname, hval)

            if event.getHeader('Content-Type') == "text/disconnect-notice":
                return self.disconnect()

            if event.getHeader('Content-Length'):
                event.addBody(data)

            # check for event in event
            if data and event.getHeader('Content-Type') == "text/event-plain":
                ievent = ESLevent("SOCKET_DATA")
                ievent.delHeader('Event-Name')
                data = data.split('\n\n')
                headers = data.pop(0)
                data = '\n\n'.join(data)
                for line in headers.splitlines():
                    hname, hval = (None, None)
                    try:
                        hname, hval = line.split(': ')
                    except (ValueError):
                        continue
                    if hname and hval:
                        hval = unquote(hval)
                        if hval[:7] == "ARRAY::":
                            ievent._add_header_array(hname, hval)
                        else:
                            ievent._add_header_string(hname, hval)
                if ievent.getHeader('Content-Length'):
                    ievent.addBody(data)
                return ievent

            return event

    def send(self, command):
        self.__send(command + "\n\n")

    def sendEvent(self, event):
        if not self.connected():
            return ESLevent("SERVER_DISCONNECTED")

        raw_data = []
        raw_data.append('sendevent %s' % (event.getType()))
        header = event.firstHeader()
        while header:
            val = event.getHeader(header)
            if isinstance(val, list):
                if len(val) > 1:
                    val = "ARRAY::%s" % ('|:'.join(val))
                else:
                    val = "%s" % (val[0])
            raw_data.append('%s: %s' % (header, val))
            header = event.nextHeader()
        body = event.getBody()
        if body:
            raw_data.append('Content-Length: %s' % (len(body)))
            raw_data.append('\n%s' % (body))
        self.__send('\n'.join(raw_data))
        return self.recvEvent()

    def sendMSG(self, event, uuid):
        pass

    def sendRecv(self, command):
        self.send(command)

        # loop until these content types are returned
        ct_list = ['api/response', 'command/reply']
        event = self.recvEvent()
        while self.connected() and event and event.getHeader('Content-Type') not in ct_list:
            print("queueing event")
            self.__event_queue.append(event)
            event = self.recvEvent()
        return event

    def setAsyncExecute(self, value):
        if value is True or str(value) == "1":
            self.__async_execute = True
            return 1
        else:
            self.__async_execute = False
            return 0

    def setEventLock(self, value):
        if value is True or str(value) == "1":
            self.__async_execute = True
            return 1
        else:
            self.__async_execute = False
            return 0

    def socketDescriptor(self):
        if self.connected():
            return self.__sock.fileno()

    def __send(self, msg):
        msg = to_bytes(msg)
        total_sent = 0
        while total_sent < len(msg):
            sent = self.__sock.send(msg[total_sent:])
            if sent == 0:
                raise RuntimeError("socket connection broken")
            total_sent = total_sent + sent

    def __receive(self):
        chunks = []
        body_len = 0
        chunk = self.__sock.recv(2048)
        if chunk:
            chunks.append(chunk)
            chunk_split = chunk.split(b'\n\n')
            headers = chunk_split.pop(0)
            body = b'\n\n'.join(chunk_split)
            for line in headers.splitlines():
                if not line:
                    continue

                k, v = (None, None)
                try:
                    k, v = line.split(b': ')
                except(ValueError):
                    continue
                if k == b'Content-Length':
                    body_len = int(v)

        need_bytes = body_len - len(body)

        if need_bytes > 0:
            bytes_recd = 0
            while bytes_recd < need_bytes:
                chunk = self.__sock.recv(min(need_bytes - bytes_recd, 2048))
                if not chunk:
                    break
                chunks.append(chunk)
                bytes_recd = bytes_recd + len(chunk)

        return (b''.join(chunks)).decode('utf=8')
