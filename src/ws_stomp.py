"""
Copyright (c) 2020 Cisco and/or its affiliates.

This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at

               https://developer.cisco.com/docs/licenses

All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
"""
import base64
import websockets
from io import StringIO
from stomp import StompFrame


class WebSocketStomp:
    def __init__(self, ws_url, user, password, ssl_ctx):
        self.ws_url = ws_url
        self.user = user
        self.password = password
        self.ssl_ctx = ssl_ctx
        self.ws = None

    async def connect(self):
        b64 = base64.b64encode(
            (self.user + ':' + self.password).encode()).decode()
        self.ws = await websockets.connect(uri=self.ws_url,
                                           extra_headers={
                                               'Authorization': 'Basic ' + b64},
                                           ssl=self.ssl_ctx)

    async def stomp_connect(self, hostname):
        print('STOMP CONNECT host=' + hostname)
        frame = StompFrame()
        frame.set_command("CONNECT")
        frame.set_header('accept-version', '1.2')
        frame.set_header('host', hostname)
        out = StringIO()
        frame.write(out)
        await self.ws.send(out.getvalue().encode('utf-8'))

    async def stomp_subscribe(self, topic):
        print('STOMP SUBSCRIBE topic=' + topic)
        frame = StompFrame()
        frame.set_command("SUBSCRIBE")
        frame.set_header('destination', topic)
        frame.set_header('id', 'my-id')
        out = StringIO()
        frame.write(out)
        await self.ws.send(out.getvalue().encode('utf-8'))

    async def stomp_send(self, topic, message):
        print('STOMP SEND topic=' + topic)
        frame = StompFrame()
        frame.set_command("SEND")
        frame.set_header('destination', topic)
        frame.set_header('content-length', str(len(message)))
        frame.set_content(message)
        out = StringIO()
        frame.write(out)
        await self.ws.send(out.getvalue().encode('utf-8'))

    # only returns for MESSAGE
    async def stomp_read_message(self):
        while True:
            message = await self.ws.recv()
            s_in = StringIO(message.decode('utf-8'))
            stomp = StompFrame.parse(s_in)
            if stomp.get_command() == 'MESSAGE':
                return stomp.get_content()
            elif stomp.get_command() == 'CONNECTED':
                version = stomp.get_header('version')
                print('STOMP CONNECTED version=' + version)
            elif stomp.get_command() == 'RECEIPT':
                receipt = stomp.get_header('receipt-id')
                print('STOMP RECEIPT id=' + receipt)
            elif stomp.get_command() == 'ERROR':
                print('STOMP ERROR content=' + stomp.get_content())

    async def stomp_disconnect(self, receipt=None):
        print('STOMP DISCONNECT receipt=' + receipt)
        frame = StompFrame()
        frame.set_command("DISCONNECT")
        if receipt is not None:
            frame.set_header('receipt', receipt)
        out = StringIO()
        frame.write(out)
        await self.ws.send(out.getvalue().encode('utf-8'))

    async def disconnect(self):
        await self.ws.close()

    def is_open(self):
        return self.ws.open
