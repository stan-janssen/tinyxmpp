# Copyright 2020 Stan Janssen

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import asyncio
import logging
import ssl as pyssl
import hmac
import secrets
import hashlib
import re
from base64 import b64encode, b64decode
from lxml import etree
from uuid import uuid4

from tinysasl import SASL

CLIENT_PORT = 5222
SERVER_PORT = 5269
logger = logging.getLogger('tinyxmpp')


class XMPPClient:
    auth_mechanisms = ['SCRAM-SHA-256', 'SCRAM-SHA-256-PLUS',
                       'SCRAM-SHA-1', 'SCRAM-SHA-1-PLUS',
                       'PLAIN', 'EXTERNAL']

    def __init__(self, jid, password):
        """
        Initialize a new XMPP Client.

        :param jid str: a fully qualified JID like user@domain.com/resource
        :param password str: the password for your JID to the server you will connect to.
        """
        self.jid = jid
        self.username, self.domain, self.resource = re.match(r"(.*)?@([a-z-.]+)/?(.*)", jid).groups()
        self.bare_jid = f"{self.username}@{self.domain}"
        self.password = password
        self.pending_iqs = {}
        self.features = []
        self.identity_category = None
        self.identity_type = None

        self.iq_handlers = {}
        self.feature_handlers = {}

    def register_feature(self, namespace, tag, stanza_type):
        """
        Register a certain feature that you will handle. This will be advertised in the <features>
        list, either at startup or in response to a discovery <query>.

        :param namespace str: The namespace for the tag that identifies the feature.
        :param tag str: The name of the tag to respond to.
        :param stanza_type str: The type of stanza that encapsulates
                                the thing: 'message', 'iq' or 'presence'.
        """


    async def connect(self, host, port=None, ssl=True, ping_interval=None):
        """
        Connect to an XMPP Server.

        :param host str: The XMPP server you want to connect to.
        :param port int: The port you want to connect to. Defaults to 5222 if you don't use SSL,
                         or to 5223 if you do.
        :param ssl: Either True (default), False, or your own ssl.SSLContext. If you specify False,
                    the connection might get upgraded using STARTTLS.
        param ping_interval float: An optional interval for XEP-0199 ping iqs. The client will
                                   automatically re-connect of no response to the ping arrives.
        """
        self.assign_event_handlers()
        self.assign_feature_handlers()
        self.assign_iq_handlers()

        self.ping_interval = ping_interval
        self.server_addr = host
        self.server_port = port or 5223 if ssl else 5222
        self.ssl = ssl
        await self._connect()

    async def _connect(self):
        while True:
            try:
                coro = asyncio.open_connection(self.server_addr, self.server_port, ssl=self.ssl)
                self.reader, self.writer = await asyncio.wait_for(coro, 10)
            except:
                logger.error("Could not connect to server, will re-try in 10 seconds.")
                await asyncio.sleep(10)
            else:
                logger.info("Connected to server.")
                break

        await self.start_reading()
        self.sasl = None

        # Things that need to be in place before we can send messages
        loop = asyncio.get_event_loop()
        self.authorized = loop.create_future()
        self.stream_id = loop.create_future()
        self.bound = loop.create_future()
        self.starttls_proceed = loop.create_future()

        await self.open_stream()
        if self.ping_interval:
            self.ping_task = loop.create_task(self.ping())

    async def disconnect(self):
        """
        Disconnect from the server.
        """
        self.reader_task.cancel()
        self.writer.close()
        await self.writer.wait_closed()

    async def open_stream(self):
        """
        Opens a new <stream:stream> with the server.
        """
        data = (f"<?xml version='1.0'?>"
                f"<stream:stream "
                f"from='{self.bare_jid}' "
                f"to='{self.server_addr}' "
                f"version='1.0' "
                f"xmlns='jabber:client' "
                f"xmlns:stream='http://etherx.jabber.org/streams'>")
        await self.send(data)
        self.stream_id = asyncio.get_event_loop().create_future()

    async def close_stream(self):
        """
        Closes the stream. If you want to send anything else, you
        first need to open a stream.
        """
        await self.send(b"</stream:stream>")
        self.stream_id = asyncio.get_event_loop().create_future()

    async def discover(self, to):
        """
        Perform XEP0030 Service Discovery on the XMPP Server.
        """
        data = "<query xmlns='http://jabber.org/protocol/disco#info'/>"
        result = await self.send_iq(element=data, type='get', from_=self.jid, to=to)
        return result

    async def send_auth(self, mechanism):
        """
        Performs SASL authentication.
        """
        # Send Auth command
        await self.stream_id
        if mechanism == 'PLAIN':
            auth_string = b64encode(b'\x00'
                                    + self.username.encode()
                                    + b'\x00'
                                    + self.password.encode())
        elif mechanism.startswith('SCRAM-SHA-1'):
            self.sasl = SASL(username=self.username,
                             password=self.password,
                             mechanism=mechanism,
                             base64=True,
                             hash_name='sha1')
            auth_string = self.sasl.initial_message()
        elif mechanism.startswith('SCRAM-SHA-256'):
            self.sasl = SASL(username=self.username,
                             password=self.password,
                             mechanism=mechanism,
                             base64=True,
                             hash_name='sha256')
            auth_string = self.sasl.initial_message()
        elif mechanism == 'EXTERNAL':
            auth_string = b'='
        data = ("<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl'"
                + " mechanism='" + mechanism + "'>"
                + ensure_str(auth_string) + "</auth>")
        await self.send(data)

    async def send_bind(self, element):
        data = (f"<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>"
                f"<resource>{self.resource}</resource></bind>")
        result = await self.send_iq(type='set', element=data)
        if result.attrib.get('type') == 'result':
            bind_element = result.find('{urn:ietf:params:xml:ns:xmpp-bind}bind')
            jid_element = bind_element.find('{urn:ietf:params:xml:ns:xmpp-bind}jid')
            jid = jid_element.text
            if jid != self.jid:
                logger.warning(f"The server gave us a different JID: {jid}")
                self.jid = jid
            self.bound.set_result(True)
        else:
            logger.warning("Something went wrong during binding", etree.tostring(result))

    async def send_message(self, to, message, **kwargs):
        """
        Send message to the connected server.
        """
        await self.bound
        if isinstance(message, etree._Element):
            message = etree.tostring(message).decode()
        if isinstance(message, bytes):
            message = message.decode()
        data = f"<message to='{to}' from='{self.jid}'>{message}</message>".encode()
        await self.send(data)

    async def send_iq(self, element=None, from_=None, to=None, type='get', iq_id=None):
        """
        Send stanza to the connected server.
        """
        data = "<iq "
        if from_:
            data += f"from='{from_}' "
        if to:
            data += f"to='{to}' "
        iq_id = iq_id if iq_id else uuid4().hex

        data += f"id='{iq_id}' "
        data += f"type='{type}'>"
        data += ensure_str(element)
        data += f"</iq>"

        # Create a future that can hold the response to this IQ
        self.pending_iqs[iq_id] = asyncio.get_event_loop().create_future()

        # Send the IQ
        await self.send(data)

        # Wait for the result to come in
        result = await self.pending_iqs[iq_id]

        # Pop the future and return the result
        self.pending_iqs.pop(iq_id)
        return result

    async def ping(self):
        """
        Send an XEP-0199 ping IQ and wait for a response.
        If we don't get a response within ping_interval, we assume we lost the connection
        and we try to re-connect.
        """
        await self.bound
        await asyncio.sleep(self.ping_interval)
        while True:
            try:
                coro = self.send_iq(b"<ping xmlns='urn:xmpp:ping'/>")
                result = await asyncio.wait_for(coro, self.ping_interval)
            except asyncio.TimeoutError:
                logger.warning("The connection to the server was lost; "
                               "no response to ping. Will reconnect.")
                break
            else:
                await asyncio.sleep(self.ping_interval)
        await self.stop_reading()
        await self._connect()

    async def send_presence(self, presence=None):
        """
        Send stanza to the connected server.
        """
        await self.stream_id
        if presence is None:
            data = "<presence/>"
        else:
            data = f"<presence type='{presence}'/>"
        await self.send(data)

    async def on_open_stream(self, element):
        """
        The server opened a new stream
        """
        self.stream_id.set_result(element.attrib.get('id'))

    async def on_close_stream(self, element):
        """
        The server decided to close the stream, so we close our stream as well.
        """
        logger.info("SERVER CLOSED THE STREAM")
        stream_id = await self.stream_id
        if element.attrib.get('id') == stream_id:
            await self.close_stream()

    async def on_features(self, element):
        """
        Process the features directive from the server.
        """
        for tag, handler in self.feature_handlers.items():
            if element.find(tag) is not None:
                await self.feature_handlers[tag](element)

    async def on_auth_mechanisms(self, element):
        """
        The server requests that we authenticate.
        """
        m = element.find('{urn:ietf:params:xml:ns:xmpp-sasl}mechanisms')
        mechanisms = [e.text for e in m.findall('{urn:ietf:params:xml:ns:xmpp-sasl}mechanism')]
        for mechanism in self.auth_mechanisms:
            # Select our preferred mechanism from the list
            if mechanism in mechanisms:
                logger.info(f"Selecting auth mechanism {mechanism}")
                await self.send_auth(mechanism)
                break
        else:
            logger.error("No compatible auth mechanism found")
            await self.close_stream()

    async def on_message(self, element):
        """
        Ṕlaceholder for your own message handler.
        """
        logger.warning("You should implement your own on_message handler")

    async def on_presence(self, element):
        """
        Placeholder for your own presence handler
        """
        logger.warning("You should implement and add your own on_presence handler")

    async def on_sasl_challenge(self, element):
        """
        Process and respond to a SASL challenge.
        """
        response = self.sasl.response(element.text)
        data = b"<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>" + response + b"</response>"
        await self.send(data)

    async def on_sasl_success(self, element):
        """
        Authentication was successful. Open a new stream.
        """
        await self.open_stream()
        self.authorized.set_result(True)

    async def on_sasl_failure(self, element):
        """
        When login over SASL has failed.
        """
        logger.error(f"Could not authenticate: {etree.tostring(element).decode()}")

    async def on_starttls_proceed(self, element):
        self.starttls_proceed.set_result(True)

    async def on_iq_prefilter(self, element):
        iq_id = element.attrib.get('id')
        iq_type = element.attrib.get('type')
        if iq_type in ('get', 'set'):
            # See if we have a specific handler for this IQ and run it
            for tag, handler in self.iq_handlers.items():
                if element.find(tag) is not None:
                    await handler(element)
                    break
            else:
                result = await self.on_iq(element)
                await self.send_iq(result,
                                   to=element.attrib.get('from'),
                                   from_=self.jid,
                                   type='result')
        elif iq_type in ('result', 'error') and iq_id in self.pending_iqs:
            # This is a response to an earlier IQ request we sent
            self.pending_iqs[iq_id].set_result(element)

    async def on_iq(self, element):
        """
        Placeholder for your own iq handler
        """
        logger.warning("Received unhandled IQ; you should implement "
                       "your own on_iq(element) handler")

    async def on_disco_query(self, element):
        """
        Respond to a Discovery Query (XEP-0030)
        """

    async def send(self, data):
        logger.debug(f"SEND {ensure_str(data)}")
        self.writer.write(ensure_bytes(data))
        await self.writer.drain()

    async def ingest(self):
        """
        Task that reads all incoming messages and puts them into the queue for handling.
        """
        while True:
            # Read the next tag from the reader
            data = await self.reader.readuntil(b">")

            # If we receive a new XML header, start a new parser.
            if data.startswith(b"<?xml"):
                parser = etree.XMLPullParser(events=['start', 'end'])

            # Feed the data to the parser
            parser.feed(data)

            # Look for tags that we have handlers for
            for event, element in parser.read_events():
                if event == 'start' and element.tag == '{http://etherx.jabber.org/streams}stream':
                    logger.debug(f"RECEIVED {ensure_str(element)}")
                    await self.on_open_stream(element)
                elif event == 'end' and element.tag in self.handlers:
                    logger.debug(f"RECEIVED {ensure_str(element)}")
                    asyncio.create_task(self.handlers[element.tag](element))

    async def validate_iq(self, element):
        """
        Validates an 'iq' stanza against the rules in chapter 8.2.3
        """
        # An IQ stanza must include an id attribute
        if element.attrib.get('id') is None:
            return False

        # An IQ stanza must be of type 'get', 'set', 'result' or 'error'
        if element.attrib.get('type') not in ('get', 'set', 'result', 'error'):
            await self.send_iq(id=element.attrib['id'],
                               type='error',
                               element='<bad-request/>')
            return False

        # An IQ stanza of type 'get' should have exactly one child
        if element.attrib.get('type') in ('get', 'set') and len(list(element)) != 1:
            await self.send_iq(id=element.attrib['id'],
                               type='error',
                               element='<bad-request/>')
            return False

        # An IQ stanza of type 'result' should have exactly zero or one child
        if element.attrib.get('type') == 'result' and len(list(element)) > 1:
            await self.send_id(id=element.attrib['id'],
                               type='error',
                               element='<bad-request/>')
            return False

        # An IQ stanza of type 'error' MAY include the original child element
        # and MUST include an <error/> child.
        if element.attrib.get('type') == 'error' and element.find('{jabber:client}error') is None:
            logger.error("No '<error/>' element in IQ error response.")
            return False
        return True

    async def stop_reading(self):
        self.reader_task.cancel()
        await asyncio.sleep(0)

    async def start_reading(self):
        self.reader_task = asyncio.create_task(self.ingest(), name='ingestion task')

    async def perform_starttls(self, element):
        # Stop the stream reading task
        await self.send("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")

        # Wait for the 'proceed' instruction and then stop reading from the socket.
        await self.starttls_proceed
        await self.stop_reading()

        # Gather the neccessary elements
        loop = asyncio.get_event_loop()
        context = pyssl.create_default_context()
        transport = self.writer.transport
        protocol = transport.get_protocol()

        # Execute start_tls on the transport (requires python 3.7)
        new_transport = await loop.start_tls(transport, protocol, context)

        # Replace the writers
        self.writer._transport = new_transport
        self.reader._transport = new_transport

        # Re-open the stream
        await self.open_stream()
        await self.start_reading()

    def assign_event_handlers(self):
        """
        Assigns handlers to different types of incoming stanzas.
        """
        self.handlers = {'{http://etherx.jabber.org/streams}features': self.on_features,
                         '{http://etherx.jabber.org/streams}stream': self.on_close_stream,
                         '{urn:ietf:params:xml:ns:xmpp-sasl}challenge': self.on_sasl_challenge,
                         '{urn:ietf:params:xml:ns:xmpp-sasl}success': self.on_sasl_success,
                         '{urn:ietf:params:xml:ns:xmpp-sasl}failure': self.on_sasl_failure,
                         '{urn:ietf:params:xml:ns:xmpp-tls}proceed': self.on_starttls_proceed,
                         '{jabber:presence}presence': self.on_presence,
                         '{jabber:client}message': self.on_message,
                         '{jabber:client}iq': self.on_iq_prefilter,
                         '{jabber:client}presence': self.on_presence}

    def assign_iq_handlers(self):
        self.iq_handlers = {'{http://jabber.org/protocol/disco#info}query': self.on_disco_query}

    def assign_feature_handlers(self):
        self.feature_handlers = {'{urn:ietf:params:xml:ns:xmpp-sasl}mechanisms': self.on_auth_mechanisms,
                                 '{urn:ietf:params:xml:ns:xmpp-bind}bind': self.send_bind,
                                 '{urn:ietf:params:xml:ns:xmpp-tls}starttls': self.perform_starttls}


def ensure_bytes(data):
    if data is None:
        return b""
    if isinstance(data, bytes):
        return data
    if isinstance(data, str):
        return data.encode()
    if isinstance(data, etree._Element):
        return etree.tostring(data)

def ensure_str(data):
    if data is None:
        return ""
    if isinstance(data, str):
        return data
    if isinstance(data, bytes):
        return data.decode()
    if isinstance(data, etree._Element):
        return etree.tostring(data).decode()
    else:
        raise ValueError("data should be str, bytes or lxml.etree._Element")
