from extensions.base.burpextensionapi import BurpExtensionApi


class HttpListener(BurpExtensionApi):

    NAME = 'some http listener (changeme)'

    # tools, as defined by burp
    # can be used to restrict handling of request/response to a specific tool
    TOOL_COMPARER = 512
    TOOL_DECODER = 256
    TOOL_EXTENDER = 1024
    TOOL_INTRUDER = 32
    TOOL_PROXY = 4
    TOOL_REPEATER = 64
    TOOL_SCANNER = 16
    TOOL_SEQUENCER = 128
    TOOL_SPIDER = 8
    TOOL_SUITE = 1
    TOOL_TARGET = 2

    # no tool restriction
    TOOL_ALL = 0

    def __init__(self):
        super().__init__()
        self.register_target_url_path = '/register/httplistener'
        self._process_msg_callback_url = self._build_callback_url('httplistener/processmsg') + '?rid={}'

    def get_register_config(self, reg_data):
        return {
            # do not restrict to any tool. change this if you want to handle request/reponse of a specific tool only
            'toolFlag': self.TOOL_ALL,
            # handle requests (requests will not be send to this extension otherwise)
            'handleRequest': True,
            # handle responses (responses will not be send to this extension otherwise)
            'handleResponse': True,
            'processMsgCallbackUrl': self._process_msg_callback_url.format(self.reg_id),
        }

    def process_http_message(self, wrapped_message):
        """
        Change the message to be sent.

        :param wrapped_message: The wrapped message
        :type wrapped_message: WrappedMessage
        :return: A list of MessageUpdate objects
        :rtype: list of `MessageUpdate`
        """
        raise NotImplemented()
