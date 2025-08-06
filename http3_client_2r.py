import asyncio
import ssl
from collections import deque, OrderedDict
from urllib.parse import urlparse
from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived, H3Event
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived, ConnectionIdIssued
from typing import Deque, Dict, Tuple
import argparse


class Config:
    DEFAULT_PORT = 443
    DEFAULT_TIMEOUT = 30


class H3ClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        self.debug = kwargs.pop("debug", None)
        self.authority = kwargs.pop("authority", None)
        super().__init__(*args, **kwargs)
        self._http = H3Connection(self._quic)
        self._request_events: Dict[int, Deque[H3Event]] = {}
        self._request_waiter: Dict[int, asyncio.Future[Deque[H3Event]]] = {}
        self._current_response_headers = OrderedDict()
        self._current_response_data = bytearray()

    def http_event_received(self, event: H3Event) -> None:
        if isinstance(event, (HeadersReceived, DataReceived)):
            stream_id = event.stream_id
            if stream_id in self._request_events:
                self._request_events[stream_id].append(event)
                if event.stream_ended:
                    request_waiter = self._request_waiter.pop(stream_id)
                    request_waiter.set_result(self._request_events.pop(stream_id))

        if isinstance(event, DataReceived):
            self._current_response_data.extend(event.data)

        if isinstance(event, HeadersReceived):
            self._current_response_headers.clear()
            for k, v in event.headers:
                self._current_response_headers[k.decode()] = v.decode()

    def quic_event_received(self, event):
        if self.debug:
            print(f"[DEBUG] QUIC event: {type(event).__name__}")

        if self._http is not None:
            for http_event in self._http.handle_event(event):
                self.http_event_received(http_event)

        if isinstance(event, StreamDataReceived):
            if self.debug:
                print(f"[DEBUG] Stream: {event.stream_id} Data: {event.data[:100]}...")

        if isinstance(event, ConnectionIdIssued):
            if self.debug:
                print(f"[DEBUG] Connection ID: {event.connection_id}")

    async def send_http_request(self, request_path, request_method="GET", request_headers=None, request_content=None):
        if request_headers is None:
            request_headers = dict()
            
        # Clear previous response data
        self._current_response_headers.clear()
        self._current_response_data = bytearray()
        
        stream_id = self._quic.get_next_available_stream_id()

        self._http.send_headers(
            stream_id,
            [
                (b":method", request_method.encode()),
                (b":scheme", b"https"),
                (b":authority", self.authority.encode()),
                (b":path", request_path.encode()),
            ] + [(k.encode(), v.encode()) for (k, v) in request_headers.items()],
            end_stream=not request_content
        )

        if request_content:
            self._http.send_data(
                stream_id=stream_id, data=request_content, end_stream=True
            )

        self.transmit()

        waiter = self._loop.create_future()
        self._request_events[stream_id] = deque()
        self._request_waiter[stream_id] = waiter
        self.transmit()

        await asyncio.shield(waiter)

        return self._current_response_data, self._current_response_headers


def create_quic_configuration():
    configuration = QuicConfiguration(is_client=True)
    configuration.alpn_protocols = H3_ALPN
    configuration.verify_mode = ssl.CERT_NONE
    return configuration


async def run_requests(url: str, debug: bool = False):
    parsed_url = urlparse(url)
    hostname = str(parsed_url.hostname)
    port = parsed_url.port or Config.DEFAULT_PORT
    configuration = create_quic_configuration()

    async with connect(
        host=hostname,
        port=port,
        create_protocol=lambda *args, **kwargs: H3ClientProtocol(*args, authority=hostname, debug=debug, **kwargs),
        configuration=configuration,
        wait_connected=True
    ) as client:

        request_headers = {
            "foo":"bar \r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Lenght: 1\r\nContent-Length: 40\r\n\r\n",
        }
        data1, headers1 = await asyncio.wait_for(
            client.send_http_request(parsed_url.path or "/",
                                   request_method="GET",
                                   request_headers=request_headers),
            timeout=Config.DEFAULT_TIMEOUT
        )

        print("="*80)
        print("First request response:")
        for k, v in headers1.items():
            print(f"{k}: {v}")
        print("Data response:")
        print(data1.decode())

        data2, headers2 = await asyncio.wait_for(
            client.send_http_request("/404",
                                   request_method="GET"),
            timeout=Config.DEFAULT_TIMEOUT
        )

        print("="*80)
        print("Second request to /404 response:")
        for k, v in headers2.items():
            print(f"{k}: {v}")
        print("Data response:")
        print(data2.decode())


def main():
    parser = argparse.ArgumentParser(description='Process a URL and a debugging flag.')
    parser.add_argument('url',
                      metavar='url',
                      type=str,
                      help='the URL to be processed')
    parser.add_argument('--debug',
                      dest='debug',
                      action='store_true',
                      help='enable debugging mode')
    parser.set_defaults(debug=False)
    args = parser.parse_args()

    try:
        asyncio.run(run_requests(args.url, debug=args.debug))
    except asyncio.TimeoutError:
        print("Timeout waiting for response.")
    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    main()