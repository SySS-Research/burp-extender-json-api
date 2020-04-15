from extensions.base.burpextensionapi import BurpExtensionApi


class ProxyListener(BurpExtensionApi):

    NAME = 'some proxy listener (changeme)'

    def __init__(self):
        super().__init__()
        self.register_target_url_path = '/register/proxylistener'
        self._process_msg_callback_url = self._build_callback_url('proxylistener/processmsg') + '?rid={}'

    def get_register_config(self, reg_data):
        return {
            # handle requests (requests will not be send to this extension otherwise)
            'handleRequest': True,
            # handle responses (responses will not be send to this extension otherwise)
            'handleResponse': True,
            'processMsgCallbackUrl': self._process_msg_callback_url.format(self.reg_id),
        }

    def process_proxy_message(self, wrapped_message):
        """
        Change the message to be sent.

        :param message: Content (full message) of the request or response
        :type message: bytearray
        :param analyzed_request: The burp analyzed request
        :type analyzed_request: dict
        :param analyzed_response: The burp analyzed response
        :type analyzed_response: dict
        :return: A list of MessageUpdate objects
        :rtype: list of `MessageUpdate`
        """
        raise NotImplemented()
