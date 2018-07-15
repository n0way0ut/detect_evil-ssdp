#!/usr/bin/env python

import socket
import http.client
import io
import random
import string as s
import osquery

class SSDPResponse(object):
    class _FakeSocket(io.BytesIO):
        def makefile(self, *args, **kw):
            return self
    def __init__(self, response):
        r = http.client.HTTPResponse(self._FakeSocket(response))
        r.begin()
        self.location = r.getheader("location")
        self.usn = r.getheader("usn")
        self.st = r.getheader("st")
    def decode(self):
        return self.__dict__

def discover(timeout=5, retries=1, mx=3):
    group = ("239.255.255.250", 1900)
    message = "\r\n".join([
        'M-SEARCH * HTTP/1.1',
        'HOST: {0}:{1}',
        'MAN: "ssdp:discover"',
        'ST: {st}','MX: {mx}','',''])
   
    socket.setdefaulttimeout(timeout)
    
    # TODO: ips = set([i[4][0] for i in socket.getaddrinfo(socket.gethostname(), None)])
    for _ in range(retries):
        rand_service = ':'.join([random.choice(s.ascii_letters + s.digits) for _ in range(3)])
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        #sock.setsockopt(socket.SOL_IP, socket.IP_MULTICAST_IF, socket.inet_aton(''))

        message_bytes = message.format(*group, st=rand_service, mx=mx).encode('utf-8')
        sock.sendto(message_bytes, group)

        while True:
            try:
                r, addr = sock.recvfrom(1024)
                response = SSDPResponse(r).decode()
            #except socket.timeout:
            except socket.error:
                response = addr = None
                break
            if addr is not None and response is not None:
                row = {}
                row["ssdp_ip"] = str(addr[0])
                row["location"] = str(response['location'])
                row["st"] = str(response['st'])
                row["usn"] = str(response['usn'])
                return row
    return


@osquery.register_plugin

class MyTablePlugin(osquery.TablePlugin):
    def name(self):
        return "detect_ssdp"

    def columns(self):
        return [
            osquery.TableColumn(name="ssdp_ip", type=osquery.STRING),
            osquery.TableColumn(name="location", type=osquery.STRING),
            osquery.TableColumn(name="st", type=osquery.STRING),
            osquery.TableColumn(name="usn", type=osquery.STRING)
        ]

    def generate(self, context):
        query_data = []
        r = discover()
        if r is not None:
            query_data.append(r)
        return query_data

if __name__ == "__main__":
    osquery.start_extension(name="ssdp_extension", version="0.1")
