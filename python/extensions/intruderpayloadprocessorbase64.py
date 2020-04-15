from extensions.base.intruderpayloadprocessor import IntruderPayloadProcessor
from libs.messageupdaterfactory import MessageUpdaterFactory


class IntruderPayloadProcessorBase64(IntruderPayloadProcessor):

    NAME = 'base64 payload processor'

    def __init__(self):
        super().__init__()

    def get_processed_payload_update(self, current_payload, original_payload, base_value):
        current_payload = current_payload.replace(b'1', b'100')

        return MessageUpdaterFactory.set_payload(current_payload)
