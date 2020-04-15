import logging

from extensions.base.proxylistener import ProxyListener
from libs.messageupdaterfactory import MessageUpdaterFactory
from models.messageupdate import MessageUpdate

LOGGER = logging.getLogger(__name__)


class ProxyIntercept(ProxyListener):

    NAME = 'Proxy Listener with intercept and drop example'

    def __init__(self):
        super().__init__()

    def process_proxy_message(self, wrapped_message):
        message_updates = []
        # check if this is a request
        if wrapped_message.request:
            #  the following 2 if conditions do the same
            if b'Password' in wrapped_message.request:
                message_updates.append(MessageUpdaterFactory.proxy_action(MessageUpdate.ACTION_DO_INTERCEPT))
            if 'Password' in self.get_decoded_body(wrapped_message.request, wrapped_message.analyzed_request):
                message_updates.append(MessageUpdaterFactory.proxy_action(MessageUpdate.ACTION_DO_INTERCEPT))
        # check if this is a response
        elif wrapped_message.response:
            #  the following 2 if conditions do the same
            if b'Security Code' in wrapped_message.response:
                message_updates.append(MessageUpdaterFactory.proxy_action(MessageUpdate.ACTION_DROP))
            if 'Security Code' in self.get_decoded_body(wrapped_message.response, wrapped_message.analyzed_response):
                message_updates.append(MessageUpdaterFactory.proxy_action(MessageUpdate.ACTION_DROP))

        return message_updates
