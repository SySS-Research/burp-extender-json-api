import base64GetAuth
from extensions.base.burpextensionapi import BurpExtensionApi


class IntruderPayloadGenerator(BurpExtensionApi):

    NAME = 'some intruder payload generator (changeme)'

    def __init__(self):
        super().__init__()
        self.register_target_url_path = '/register/intruderpayloadgenerator'
        self._has_more_payloads_callback_url = self._build_callback_url(
            'intruderpayloadgenerator/hasmorepayloads') + '?rid={}'
        self._get_next_payload_callback_url = self._build_callback_url(
            'intruderpayloadgenerator/getnextpayload') + '?rid={}'
        self._reset_callback_url = self._build_callback_url(
            'intruderpayloadgenerator/reset') + '?rid={}'
        self.attack_info = b''

    def get_register_config(self, reg_data):
        self.attack_info = base64.b64decode(reg_data['requestTemplate'])
        return {
            'hasMorePayloadsCallbackUrl': self._has_more_payloads_callback_url.format(self.reg_id),
            'getNextPayloadCallbackUrl': self._get_next_payload_callback_url.format(self.reg_id),
            'resetCallbackUrl': self._reset_callback_url.format(self.reg_id)
        }

    def has_more_payloads(self):
        raise NotImplemented()

    def get_next_payload_update(self, base_value):
        """
        Get the modified payload

        :type base_value: str
        :param base_value: The base value of the payload
        :return: A list of MessageUpdate objects
        :rtype: list of `MessageUpdate`
        """
        raise NotImplemented()

    def reset(self):
        raise NotImplemented()
