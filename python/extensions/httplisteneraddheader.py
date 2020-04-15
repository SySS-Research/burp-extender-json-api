import logging

from extensions.base.httplistener import HttpListener
from libs.messageupdaterfactory import MessageUpdaterFactory

LOGGER = logging.getLogger(__name__)


class HttpListenerAddHeader(HttpListener):

    NAME = 'http listener add header'

    def __init__(self):
        super().__init__()

    def get_register_config(self, reg_data):
        config = super().get_register_config(reg_data)
        # restrict to requests made by proxy or repeater
        config['toolFlag'] = self.TOOL_PROXY | self.TOOL_REPEATER
        return config

    def process_http_message(self, wrapped_message):
        updates = []
        # requests made with the repeater only
        # please note it is also possible to restrict the handling to specific tools (repeater, proxy, ...)
        # via the configuration (see get_reg_config()), which may increase performance
        if wrapped_message.has_request() and self.TOOL_REPEATER == wrapped_message.tool_flag:
            headers = wrapped_message.request_headers
            # add custom header if request has the "X-Requested-With" header
            if wrapped_message.has_header('X-Requested-With', headers):
                LOGGER.info('Adding custom header')
                headers.append('X-custom-header: foobar')
                updates.append(MessageUpdaterFactory.update_request_headers(headers))

        return updates
