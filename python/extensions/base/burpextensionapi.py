import logging
from http.client import HTTPConnection
import json

from libs.registry import Registry
from models.wrappedmessage import WrappedMessage

LOGGER = logging.getLogger(__name__)


class BurpExtensionApi:

    # should be set at startup
    LOCAL_PORT = -1
    TARGET_PORT = -1
    CALLBACK_URL_BASE = 'http://localhost:{}/'
    AUTH_TOKEN = ''

    TARGET_HOST = 'localhost'
    NAME = 'undefined. this should be a unique name'

    def __init__(self):
        HTTPConnection.debuglevel = 1
        self.client = HTTPConnection(self.TARGET_HOST, self.TARGET_PORT)
        self.register_target_url_path = ''
        self.unregister_target_url_path = '/reset'
        self.reg_id = -1
        self.callback_url_path = 'getregdata'
        self.request_headers = {'Content-type': 'application/json', 'Authorization': self.AUTH_TOKEN}

    def register(self):
        LOGGER.info('Registering {}'.format(self.NAME))
        self.reg_id = Registry.register(self.NAME, self)
        if not self._do_register_request():
            Registry.unregister(self.NAME)

    def unregister(self):
        self._do_unregister_request()
        Registry.unregister(self.NAME)

    def get_register_config(self, reg_data):
        """
        Get the registration config

        :param reg_data: Registration information provided by the burp plugin
        :return: The registration information, i.e. callbacks, caption, settings, ...
        :rtype: dict
        """
        return {}

    def _build_callback_url(self, path):
        # TODO use uri builder
        url = self.CALLBACK_URL_BASE
        if not (url.endswith('/') or path.startswith('/')):
            url = url + '/'

        return url + path

    def _do_unregister_request(self):
        params = self.NAME
        response = self._do_json_request(self.unregister_target_url_path, params)
        try:
            data = response.read()
            json_response = json.loads(data)
            if 'ok' == json_response['status']:
                LOGGER.info('Un-Registration successful for {}'.format(self.NAME))
                return True
        except KeyError:
            LOGGER.warning('Invalid response')

        return False

    def _do_register_request(self):
        params = {
            'name': self.NAME,
            'callbackUrl': self._build_callback_url(self.callback_url_path) + '?rid={}'.format(self.reg_id)
        }
        if not self.register_target_url_path.startswith('/'):
            self.register_target_url_path = '/' + self.register_target_url_path
        response = self._do_json_request(self.register_target_url_path, params)
        try:
            data = response.read()
            json_response = json.loads(data)
            if 'ok' == json_response['status']:
                LOGGER.debug('Registration request successful for {}'.format(self.NAME))
                if json_response['alreadyRegistered']:
                    LOGGER.info('Re-registered extension with new id')
                return True
        except KeyError:
            LOGGER.warning('Invalid response')

        return False

    def _do_json_request(self, url, json_dict=None, headers=None):
        req_headers = self.request_headers
        if headers is not None:
            req_headers = {**req_headers, **headers}
        params = None
        if json_dict is not None:
            params = json.dumps(json_dict)
        self.client.request('POST', url, params, req_headers)
        response = self.client.getresponse()
        if 401 == response.status:
            LOGGER.error('Request unauthorized, please check your auth token')


        return response

    def get_proxy_history(self, start, stop):
        """
        Get the burp proxy history

        :param start: First entry to fetch from the list
        :type start: int
        :param stop: Last entry to fetch from the list
        :type stop: int
        :return: List of WrappedMessage containing the request/response
        :rtype list of WrappedMessage
        """
        result = []
        params = {'start': start, 'stop': stop}
        response = self._do_json_request('/getproxyhistory', params)
        try:
            message = response.read()
            # should contain list of objects like:
            # {"request":"base64...",
            # "response":"base64...",
            # "analyzedRequest":
            #   {"bodyOffset":516,"url":"http...","contentType":0,"headers":["GET...","Host: ...","User-Agent: ...",
            #   "Cookie: ..."],"method":"GET","parameters":[{"nameStart":123,"nameEnd":456,"valueStart":329,
            #   "valueEnd":334,"name":"foobar","value":"de-DE","type":2},}]},
            # "analyzedResponse":
            #   {"bodyOffset":254,"statedMimeType":"HTML","inferredMimeType":"HTML","cookies":[],
            # "  statusCode":200,"headers":["HTTP/1.1 200 OK","Cache-Control: ...","Content-Length: 123"]}}
            result = json.loads(WrappedMessage(message))
        except:
            LOGGER.exception('Error while getting proxy history')

        return result

    @staticmethod
    def get_header(header, analyzed_request_response):
        """
        Get the given header from a request or an empty string, if the header is not found.

        :param header: Header name
        :type header: str
        :param analyzed_request_response: The burp analyzed request or response
        :type analyzed_request_response: dict
        :return: str or None
        """
        return WrappedMessage.get_header(header, analyzed_request_response['headers'])

    def get_message_encoding(self, analyzed_message):
        """
        Read encoding from analyzed request/response content-type header

        :param analyzed_message: analyzed request or response
        :type analyzed_message: dict
        :return: encoding, i.e. "utf-8"
        :rtype: str
        """
        encoding = 'utf-8'
        content_type = self.get_header('content-type', analyzed_message)
        if content_type is not None:
            content_type = content_type.lower()
            enc_offset_start = content_type.find('charset=')
            if enc_offset_start > -1:
                enc_offset_stop = content_type.find(';', enc_offset_start + 1)
                if enc_offset_stop < 1:
                    enc_offset_stop = len(content_type)
                encoding = content_type[enc_offset_start + len('charset='):enc_offset_stop]

        return encoding

    def get_decoded_body_and_encoding(self, message, analyzed_message):
        """
        Get the decoded body and encoding

        :param message: request or response
        :param analyzed_message: analyzed request or response
        :return: Tuple of decoded body (str), encoding (str)
        :rtype tuple
        """
        offset = analyzed_message['bodyOffset']
        encoding = self.get_message_encoding(analyzed_message)
        # get body
        if offset > 0:
            body = message[offset:]
            return body.decode(encoding), encoding
        LOGGER.warning('Invalid offset in message')
        return None, None

    def get_decoded_body(self, message, analyzed_message):
        """
        Get the decoded body

        :param message: request or response
        :param analyzed_message: analyzed request or response
        :return: Decoded body
        :rtype: str
        """
        return self.get_decoded_body(message, analyzed_message)[0]
