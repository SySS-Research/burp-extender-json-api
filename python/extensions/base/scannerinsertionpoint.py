from extensions.base.burpextensionapi import BurpExtensionApi


class ScannerInsertionPoint(BurpExtensionApi):

    NAME = 'some scanner insertion point (changeme)'

    def __init__(self):
        super().__init__()
        self.register_target_url_path = '/register/scannerinsertionpointprovider'
        self._build_request_callback_url = self._build_callback_url('scannerinsertionpoint/buildrequest') + '?rid={}'

    def get_register_config(self, reg_data):
        return {
            'callbackUrl': self._build_request_callback_url.format(self.reg_id),
            'insertionPointNames': ['insertionpointname'],
        }

    def build_request_update(self, request, analyzed_request, payload, name):
        raise NotImplemented()
