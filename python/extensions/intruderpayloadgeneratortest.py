from extensions.base.intruderpayloadgenerator import IntruderPayloadGenerator
from libs.messageupdaterfactory import MessageUpdaterFactory


class IntruderPayloadGeneratorTest(IntruderPayloadGenerator):

    NAME = 'Test Payload Generator'

    def __init__(self):
        super().__init__()
        self.has_payload = True

    def has_more_payloads(self):
        return self.has_payload

    def get_next_payload_update(self, base_value):
        self.has_payload = False
        return [MessageUpdaterFactory.set_payload('test')]

    def reset(self):
        self.has_payload = True
