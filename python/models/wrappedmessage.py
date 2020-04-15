import base64


class WrappedMessage(object):

    def __init__(self, original_dict):
        super().__init__()
        self.original_dict = original_dict

    @property
    def tool_flag(self):
        try:
            return self.original_dict['toolFlag']
        except KeyError:
            pass
        return None

    @property
    def request(self):
        keys = [
            # AnalyzedMessage
            ['request'],
            # SessionHandlingActionRequest
            ['currentRequest', 'request'],
            # InterceptedMessage
            ['message', 'messageInfo', 'request'],
        ]
        data = self._get_data(keys)
        if data is not None:
            data = base64.b64decode(data)

        return data

    @property
    def response(self):
        keys = [
            ['response'],
            ['message', 'messageInfo', 'response'],
        ]
        data = self._get_data(keys)
        if data is not None:
            data = base64.b64decode(data)

        return data

    @property
    def analyzed_request(self):
        keys = [
            ['analyzedRequest'],
            # SessionHandlingActionRequest
            ['currentRequest', 'analyzedRequest'],
        ]
        return self._get_data(keys)

    @property
    def analyzed_response(self):
        keys = [
            ['analyzedResponse'],
        ]
        return self._get_data(keys)

    @property
    def request_headers(self):
        if self.analyzed_request:
            return self.analyzed_request['headers']

        return None

    @property
    def response_headers(self):
        if self.analyzed_response:
            return self.analyzed_response['headers']

        return None

    def _get_data(self, keys):
        result = self.original_dict
        for keylist in keys:
            i = 0
            for k in keylist:
                try:
                    result = result[k]
                    i += 1
                except KeyError:
                    break
            if len(keylist) == i:
                return result

        return None

    def has_request(self):
        return self.request is not None

    def has_response(self):
        return self.response is not None

    @staticmethod
    def get_header(header, request_or_response_headers):
        for the_header in request_or_response_headers:
            if the_header.lower().startswith(header.lower()):
                return the_header
        return None

    @staticmethod
    def has_header(header, request_or_response_headers):
        return WrappedMessage.get_header(header, request_or_response_headers) is not None
