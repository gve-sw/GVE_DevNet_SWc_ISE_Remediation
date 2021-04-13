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
import io


class StompFrame:
    def __init__(self):
        self.headers = {}
        self.command = None
        self.content = None

    def get_command(self):
        return self.command

    def set_command(self, command):
        self.command = command

    def get_content(self):
        return self.content

    def set_content(self, content):
        self.content = content

    def get_header(self, key):
        return self.headers[key]

    def set_header(self, key, value):
        self.headers[key] = value

    def write(self, out):
        out.write(self.command)
        out.write('\n')
        for key in self.headers:
            out.write(key)
            out.write(':')
            out.write(self.headers[key])
            out.write('\n')
        out.write('\n')
        if self.content is not None:
            out.write(self.content)
        out.write('\0')

    @staticmethod
    def parse(input):
        frame = StompFrame()
        frame.command = input.readline().rstrip('\r\n')
        for line in input:
            line = line.rstrip('\r\n')
            if line == '':
                break
            (name, value) = line.split(':')
            frame.headers[name] = value
        frame.content = input.read()[:-1]
        return frame
