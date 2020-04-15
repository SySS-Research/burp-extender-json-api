from extensions.base.burpextensionapi import BurpExtensionApi


class ScannerCheck(BurpExtensionApi):

    NAME = 'my scanner check extension'

    def __init__(self):
        super().__init__()
        self.register_target_url_path = '/register/scannercheck'
        self._passive_callback_url = self._build_callback_url('scannercheck/passive') + '?rid={}'
        self._active_callback_url = self._build_callback_url('scannercheck/active') + '?rid={}'
        self._consolidate_callback_url = self._build_callback_url('scannercheck/consolidate') + '?rid={}'

    def get_register_config(self, reg_data):
        return {
            'passiveScanCallbackUrl': self._passive_callback_url.format(self.reg_id),
            'activeScanCallbackUrl': self._active_callback_url.format(self.reg_id),
            'consolidateDuplicateCallbackUrl': self._consolidate_callback_url.format(self.reg_id),
        }

    def get_passive_scan_issues(self, wrapped_message):
        raise NotImplemented()

    def get_active_scan_issues(self, wrapped_message):
        raise NotImplemented()

    # return -1 to report the existing issue only, 0 to report both issues, and 1 to report the new issue only
    def get_consolidated_issues_result(self, existing_issue, new_issue):
        raise NotImplemented()
