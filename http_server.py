

import asyncio
import logging
import mimetypes
import http
import urllib
from urllib.parse import ParseResult
import os
from dataclasses import dataclass


# A more general and absract Server concept for the precursor of our HTTP server
class Server:
    def __init__(self, addr=None, port=8000, __logging=False, debug=False):
        self.addr = "localhost" if addr is None else addr
        self.port = port
        self.client_pool = dict()
        self.logging = __logging
        self.debug = debug
        self.init_logger()

    def __str__(self):
        return self.__class__.__name__

    def init_logger(self):
        self.logger = logging.getLogger(f"{self}")
        if self.logging and self.debug:
            logging.basicConfig(level=logging.DEBUG)

        elif self.logging:
            logging.basicConfig(level=logging.INFO)
        else:
            logging.basicConfig(level=logging.WARNING)

    async def on_new_client(self, reader: asyncio.StreamReader,
                            writer: asyncio.StreamWriter):
        __id = writer.get_extra_info("peername")
        self.logger.info(f"New client: {__id} connected!")

        self.client_pool[__id] = (reader, writer)
        asyncio.create_task(self.serve_task(__id))

    def fetch_streams(self, client_id: tuple):
        if client_id not in self.client_pool:
            return (None, None)
        return self.client_pool[client_id]

    async def send_to(self, writer: asyncio.StreamWriter, data):
        # guard for direct string sending
        data = self.encode_str(data) if type(data) is str else data
        writer.write(data)
        await writer.drain()

    async def recv_from(self, reader: asyncio.StreamReader, length=1024, end=None):
        if reader is None:
            return
        if end:
            return await reader.readuntil(separator=end)
        else:
            return await reader.read(length)

    @staticmethod
    def encode_str(data):
        encoding = "utf-8"
        return data.encode(encoding)

    async def serve_task(client_id):
        # Do something!
        pass

    async def serve(self):
        self.logger.info(
            f"Starting '{self}' on http://{self.addr}:{self.port}...")
        self.server = await asyncio.start_server(
            self.on_new_client, self.addr, self.port)
        async with self.server:
            await self.server.serve_forever()

    def run(self):
        asyncio.run(self.serve())


# encapsulate response and request data

@dataclass
class HTTPResponse:
    status_code: int
    status_phrase: str
    headers: dict
    body: bytes
    mimetype: str

# Encapsulate into a different type for more control (later on)


class ParsedURL():
    def __init__(self, parse_result: ParseResult, **other_parts):
        pr = parse_result
        self.scheme = pr.scheme
        self.netloc = pr.netloc
        self.path = pr.path
        self.params = pr.params
        if pr.query:
            self.query = dict(f.split('=')
                              for f in pr.query.split('&'))
        else:
            self.query = pr.query
        self.fragment = pr.fragment
        self.other = other_parts


@dataclass
class HTTPRequest:
    headers: dict
    body: bytes
    method: str
    requested_url: ParsedURL


class HttpServer(Server):
    CRLF = b"\r\n"

    ERROR_STATUS_HTML = {
        404: b"""
    <!DOCTYPE html> 
    <html> 
    <h1> 404 Not Found </h1> 
    <p> The requested resource was not found on this server. Sorry :(( </p>
    </html>
    """,

        400: b"""
    <!DOCTYPE html> 
    <html> 
    <h1> 400 Bad Request </h1> 
    <p> Your browser sent a request we can't understand! :*-O </p>
    </html>
    """,

        501: b"""
    <!DOCTYPE html> 
    <html> 
    <h1> 501 Not Implemented </h1> 
    <p> The requested method is not implemented by this server :-( </p>
    </html>
    """,

    }

    parser = urllib.parse

    def __init__(self, addr=None, port=8000, logging=False, debug=False, version="1.1"):
        super().__init__(addr, port, logging, debug)
        self.allowed_requests = ["GET", "POST"]
        self.version = version
        self.callbacks = []

    @staticmethod
    def get_ext(filename):
        sep = b"." if type(filename) is bytes else "."
        return "." + filename.split(sep)[-1]

    @classmethod
    def parse_request_headers(cls, raw_request: bytes) -> HTTPRequest:
        fields = raw_request.split(cls.CRLF)
        first = fields.pop(0)
        method, URI, version = first.split(b" ")
        fields_dict = dict()
        for field in fields:
            if not field:
                continue
            key, value = field.split(b": ")
            fields_dict[key] = value
        req = HTTPRequest(headers=fields_dict, body=b"",
                          method=method, requested_url=cls.parse_url(URI))
        return req

    def parse_body(self, raw_request: bytes) -> HTTPRequest:
        pass

    def dead_message(self, msg):
        return msg == b''

    # prepare response headers
    def prepare_headers(self, response: HTTPResponse):
        # placeholder
        top = f"HTTP/{self.version} {response.status_code} {response.status_phrase}\r\n"
        headers = {
            "Content-Type": f"{response.mimetype}; charset=utf-8",
            "Server": "Free-HTTP-Server",
            "Allow": ", ".join(self.allowed_requests),
            "Connection": "close",
            "Content-Length": str(len(response.body))
        }

        headers_str = (self.CRLF.decode()).join([f"{key}: {value}" for key,
                                                 value in headers.items()])
        return self.encode_str(top + headers_str)

    def valid_request(self, request: HTTPRequest):
        # placeholder
        return True

    def status_resolution(self, request: HTTPRequest, response_body: bytes):
        s = http.HTTPStatus
        if type(self) is HttpServer:
            status = s.NOT_IMPLEMENTED
        if not self.valid_request(request):
            status = s.BAD_REQUEST
        elif response_body is None:
            status = s.NOT_FOUND
        elif request.method.decode() not in self.allowed_requests:
            print(request.method.decode(), "lol")
            status = s.METHOD_NOT_ALLOWED
        else:
            status = s.OK

        return status.value, status.phrase

    @staticmethod
    def erronous_code():
        pass

    def finalize_body(self, response):
        if response.status_code in [200, ]:
            return response.body
        body = self.ERROR_STATUS_HTML[response.status_code]
        return body

    @classmethod
    def mimetype_resolution(cls, filename):
        # guard against unknown extension
        if filename is None:
            return "text/html"
        ext = cls.get_ext(filename=filename)
        if ext not in mimetypes.types_map:
            return "text/plain"
        return mimetypes.types_map[ext]

    def construct_response(self, request, filename, body):
        code, phrase = self.status_resolution(request, response_body=body)
        response = HTTPResponse(code, phrase, None, body,
                                self.mimetype_resolution(filename))
        response.body = self.finalize_body(response)
        headers = self.prepare_headers(response)
        response.headers = headers
        return response

    @classmethod
    def raw_response(cls, http_response: HTTPResponse):
        return \
            http_response.headers \
            + cls.CRLF*2 \
            + http_response.body

    async def recv_request_headers(self, reader: asyncio.StreamReader):
        headers = await self.recv_from(reader, end=self.CRLF*2)
        return headers

    async def recv_request_body(self, reader: asyncio.StreamReader, content_length: int):
        body = await self.recv_from(reader, length=content_length)
        return body

    async def handle_request(self, reader, headers):
        req = self.parse_request_headers(headers)
        content_length = int(req.headers.get(b"Content-Length", 0))
        if content_length > 0:
            body = await self.recv_request_body(reader, content_length=content_length)
            req.body = body
        return req

    async def handle_response(self, request):
        response = self.construct_response(
            request, filename=None, body=None)
        return response

    async def serve_for(self, client_id):
        # to do: refactor and reduce this function into smaller parts #partially ok
        r, w = self.fetch_streams(client_id)
        try:
            headers = await self.recv_request_headers(r)
        except asyncio.exceptions.IncompleteReadError:
            # read returned b'' connection ends
            self.logger.info(f"Client {client_id} disconnected!")
            return True
        req = await self.handle_request(r, headers)
        self.logger.debug(
            f"Received request from {client_id}: {req.method} {req.requested_url.path}")
        response = await self.handle_response(req)

        await self.send_to(w, self.raw_response(response))
        # return to the main loop a little
        await asyncio.sleep(0.0001)

    async def serve_task(self, client_id):
        connection_closed = False
        while not connection_closed:
            connection_closed = await self.serve_for(client_id)

    @classmethod
    def parse_url(cls, URI):
        # guard against URI being bytes
        url = URI.decode() if type(URI) is bytes else URI
        parsed = cls.parser.urlparse(url)
        return ParsedURL(parsed)


# A more literal, direct web server. Handles content allocation and fetching as well
# Different than an http server in a sense that it also specifies how the content will be handled
#

# loc_mapping supports dynamic mapping for content, separate from the literal file structure of the server


class WebServer(HttpServer):
    def __init__(self, loc_mapping={}, addr=None, port=8000,
                 logging=False, debug=False, http_version="1.1", root_dir=".", action_callback={}):
        # dynamic mapping
        self.loc_resource = loc_mapping
        self.root_dir = root_dir
        super().__init__(addr, port, logging, debug, http_version)
        self.action_callback = action_callback

    def get_info_from_url(self, url: ParsedURL):
        in_mapping = url.path in self.loc_resource
        if not in_mapping:
            filepath = url.path
            if filepath.startswith('/'):
                # remove the first slash to get file paths correctly
                filepath = filepath[1:]
            filepath = os.path.join(self.root_dir, filepath)
            filename = os.path.basename(filepath)
        else:
            filename = None
            filepath = None

        return filepath, filename, in_mapping

    def resource_resolution(self, request: HTTPRequest):
        filepath, filename, in_mapping = self.get_info_from_url(
            request.requested_url)
        self.logger.debug(
            f"path: {request.requested_url.path}, filename: {filename}, filepath: {filepath}")
        if not in_mapping:
            try:
                file = open(filepath, "rb")
            except FileNotFoundError:
                # 404
                return None
            data = file.read()
            return data, filename
        return self.loc_resource[request.requested_url.path], filename

    async def handle_response(self, request):
        # look up the action table
        action = self.action_callback.get(request.requested_url.path, None)
        if action:
            try:
                action_result = action(request)
            except:
                self.logger.warning(f"could not call action {action}")
                action_result = None

        if (resources := self.resource_resolution(request)):
            body, filename = resources
            # if action result is overriding mapping
            body = action_result if action_result is not None else body
        else:
            if resources is None:
                body = None
                filename = None
        
        response = self.construct_response(
            request, filename=filename, body=body)
        return response

    def look_up_action(self, request):
        return self.action_callback.get(
            request.requested_url.path, None)

    def attach_action(self, path, action):
        if not callable(action):
            raise TypeError(f"action object must be callable!")
        self.action_callback[path] = action



        


def main():
    def greet(request: HTTPRequest):
        q = request.requested_url.query
        if 'name' in q:
            return f"""
                <!DOCTYPE html>
                <html>
                <h1> Welcome to Free-HTTP-Server {q['name']}! </h1>
                <p> This is a minimalistic HTTP server implementation in Python. Enjoy your stay! </p>
                </html>
                """.encode()
                
    loc_mapping = {
        "/": b"""
        <!DOCTYPE html>
        <html>
        <h1> Welcome to Free-HTTP-Server! </h1>
        <p> This is a minimalistic HTTP server implementation in Python. Enjoy your stay! </p>
        </html>
        """,
        "/hello_world": b"""
        <!DOCTYPE html>
        <html>
        <h1> Welcome to Free-HTTP-Server! </h1>
        <p> Hello world! </p>
        </html>
        """
    }
    server = WebServer(port=31331, logging=True, debug=True,
                       root_dir="./www", loc_mapping=loc_mapping)
    server.attach_action('/', greet)
    server.run()


if __name__ == "__main__":
    main()
