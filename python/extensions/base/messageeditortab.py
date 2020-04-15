from extensions.base.burpextensionapi import BurpExtensionApi


class MessageEditorTab(BurpExtensionApi):

    NAME = 'some message processor (changeme)'

    def __init__(self):
        super().__init__()
        self.register_target_url_path = '/register/messageeditortab'
        self._get_text_callback_url = self._build_callback_url('msgeditor/sendable') + '?rid={}'
        self._set_text_callback_url = self._build_callback_url('msgeditor/readable') + '?rid={}'

        self.caption = self.NAME
        self.editable = True
        self.cache_enabled = True

    def get_register_config(self, reg_data):
        return {
            'caption': self.caption,
            'getMessageCallbackUrl': self._get_text_callback_url.format(self.reg_id),
            'setMessageCallbackUrl': self._set_text_callback_url.format(self.reg_id),
            'editable': self.editable,
            'cacheEnabled': self.cache_enabled,
        }

    def get_readable_content_updates(self, wrapped_message):
        """
        Change the message to be viewed in burp (i.e. decode).

        :param wrapped_message: The wrapped message
        :type wrapped_message: WrappedMessage
        :return: A list of MessageUpdate objects
        :rtype: list of `MessageUpdate`
        """
        raise NotImplemented()

    def get_sendable_content_updates(self, message, analyzed_request, analyzed_response):
        """
        Change the message to be sent again (i.e. encode).

        :param wrapped_message: The wrapped message
        :type wrapped_message: WrappedMessage
        :return: A list of MessageUpdate objects
        :rtype: list of `MessageUpdate`
        """
        raise NotImplemented()
