import base64
from models.messageupdate import MessageUpdate


class MessageUpdaterFactory:

    @staticmethod
    def update_parameter(param_name, param_value):
        update = MessageUpdate()
        update.action = MessageUpdate.UPDATE_PARAMETER
        update.paramName = param_name
        update.paramValue = param_value
        return update

    @staticmethod
    def add_parameter(param_name, param_value, param_type):
        update = MessageUpdate()
        update.action = MessageUpdate.ADD_PARAMETER
        update.paramName = param_name
        update.paramValue = param_value
        update.paramType = param_type
        return update

    @staticmethod
    def del_parameter(param_name):
        update = MessageUpdate()
        update.action = MessageUpdate.DEL_PARAMETER
        update.paramName = param_name
        return update

    @staticmethod
    def replace_request_response(body, encoding='utf-8'):
        update = MessageUpdate()
        update.action = MessageUpdate.REPLACE_REQUEST_RESPONSE
        update.body = base64.b64encode(body).decode(encoding)
        return update

    @staticmethod
    def set_payload(body, encoding='utf-8'):
        # handling for payloads is basically like replacing the request/response
        # in the java code
        return MessageUpdaterFactory.replace_request_response(body, encoding)

    @staticmethod
    def replace_request_body(body, encoding='utf-8'):
        update = MessageUpdate()
        update.action = MessageUpdate.REPLACE_REQUEST_BODY
        update.body = base64.b64encode(body).decode(encoding)
        return update

    @staticmethod
    def replace_response_body(body, encoding='utf-8'):
        update = MessageUpdate()
        update.action = MessageUpdate.REPLACE_RESPONSE_BODY
        update.body = base64.b64encode(body).decode(encoding)
        return update

    @staticmethod
    def build_new_http_message(headers, body, encoding='utf-8'):
        update = MessageUpdate()
        # WARNING: this will overwrite the whole message, previous changes will be ignored!
        update.action = MessageUpdate.BUILD_HTTP_MESSAGE
        update.headers = headers
        update.body = base64.b64encode(body).decode(encoding)
        return update

    @staticmethod
    def update_request_headers(headers):
        update = MessageUpdate()
        update.action = MessageUpdate.UPDATE_REQUEST_HEADERS
        update.headers = headers
        return update

    @staticmethod
    def base64_decode_body(data, encoding='utf-8'):
        update = MessageUpdate()
        update.action = MessageUpdate.BASE64_DECODE_BODY
        update.body = base64.b64encode(data).decode(encoding)
        return update

    @staticmethod
    def get_body(data, encoding='utf-8'):
        update = MessageUpdate()
        update.action = MessageUpdate.GET_BODY
        update.body = base64.b64encode(data).decode(encoding)
        return update

    @staticmethod
    def proxy_action(action):
        update = MessageUpdate()
        # i.e. MessageUpdate.ACTION_FOLLOW_RULES
        update.action = action
        return update

    @staticmethod
    def no_action():
        return MessageUpdate()
