from libs.messageupdaterfactory import MessageUpdaterFactory
from extensions.base.scannerinsertionpoint import ScannerInsertionPoint


class ScannerInsertionPointTest(ScannerInsertionPoint):

    NAME = 'scanner insertion point test'

    def __init__(self):
        super().__init__()

    def build_request_update(self, request, analyzed_request, payload, name):
        update = MessageUpdaterFactory.replace_request_body(b'foobargrah')
        return [update]
