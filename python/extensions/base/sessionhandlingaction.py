from extensions.base.burpextensionapi import BurpExtensionApi


class SessionHandlingAction(BurpExtensionApi):

    NAME = 'some session handler action  (changeme)'

    def __init__(self):
        super().__init__()
        self.register_target_url_path = '/register/sessionhandlingaction'
        self._perform_url = self._build_callback_url('sessionhandlingaction/perform') + '?rid={}'

    def get_register_config(self, reg_data):
        return {
            'performCallbackUrl': self._perform_url.format(self.reg_id),
        }

    def perform_action(self, wrapped_message, analyzed_macros):
        raise NotImplemented()
