import logging
import re

from extensions.base.sessionhandlingaction import SessionHandlingAction
from libs.messageupdaterfactory import MessageUpdaterFactory

LOGGER = logging.getLogger(__name__)


class SessionHandlingReplaceAuth(SessionHandlingAction):

    NAME = 'Replace authentication token'

    def __init__(self):
        super().__init__()

    def perform_action(self, wrapped_message, analyzed_macros):
        analyzed_request = wrapped_message.analyzed_request
        sec_tok = ''
        for macro in analyzed_macros:
            sec_tok = re.findall(r'<a:SecurityToken>(.*)</a:SecurityToken>', macro.response.decode())[0]

        LOGGER.info('Setting security token to: {}'.format(sec_tok))

        body, encoding = self.get_decoded_body_and_encoding(wrapped_message.request, analyzed_request)
        body = re.sub(r'<pmg1:SecurityToken>(.*)</pmg1:SecurityToken>',
                      '<pmg1:SecurityToken>{}</pmg1:SecurityToken>'.format(sec_tok), body)
        body = body.encode(encoding)

        return [MessageUpdaterFactory.replace_request_body(body)]
