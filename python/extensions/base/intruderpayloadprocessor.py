import base64

from extensions.base.burpextensionapi import BurpExtensionApi


class IntruderPayloadProcessor(BurpExtensionApi):

    NAME = 'some payload processor (changeme)'

    def __init__(self):
        super().__init__()
        self.register_target_url_path = '/register/intruderpayloadprocessor'
        self.callback_url_path = 'intruder/processpayload'

    def get_processed_payload_update(self, current_payload, original_payload, base_value):
        raise NotImplemented()
