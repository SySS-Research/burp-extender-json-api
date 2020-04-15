import logging
import json
from lxml import etree

from extensions.base.messageeditortab import MessageEditorTab
from libs.messageupdaterfactory import MessageUpdaterFactory

LOGGER = logging.getLogger(__name__)


class MessageEditorTabPrettyPrint(MessageEditorTab):

    NAME = 'PrettyPrint'

    def __init__(self):
        super().__init__()

    def get_readable_content_updates(self, wrapped_message):
        result = []
        analyzed_request = wrapped_message.analyzed_request
        analyzed_response = wrapped_message.analyzed_response

        is_request = analyzed_request is not None
        analyzed_data = analyzed_request
        message = wrapped_message.request
        if not is_request:
            analyzed_data = analyzed_response
            message = wrapped_message.response

        # noinspection PyBroadException
        try:
            body, encoding = self.get_decoded_body_and_encoding(message, analyzed_data)
            pretty_body = ''

            try:
                # dump pretty
                pretty_body = json.dumps(json.loads(body), indent=4, sort_keys=False)
                # re-encode
                pretty_body = pretty_body.encode(encoding)
            except json.JSONDecodeError:
                LOGGER.info('Content is not json')
                try:
                    xml = etree.fromstring(body)
                    # etree will encode automatically
                    pretty_body = etree.tostring(xml, pretty_print=True, encoding=encoding)
                except etree.LxmlError:
                    LOGGER.info('Content is not xml. Giving up')

            if pretty_body:
                # create update object
                if is_request:
                    result.append(MessageUpdaterFactory.replace_request_body(pretty_body))
                else:
                    result.append(MessageUpdaterFactory.replace_response_body(pretty_body))

        except Exception:
            LOGGER.exception('Error in extension.')

        return result

    def get_sendable_content_updates(self, message, analyzed_request, analyzed_response):
        # no action needed
        return []
