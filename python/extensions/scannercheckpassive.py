import logging

from extensions.base.scannercheck import ScannerCheck
from models.scanissue import ScanIssue

LOGGER = logging.getLogger(__name__)


class PassiveScannerCheck(ScannerCheck):

    NAME = 'Passive scanner check test'

    def __init__(self):
        super().__init__()

    def get_passive_scan_issues(self, wrapped_message):
        scan_issue = ScanIssue()
        scan_issue.confidence = 'Certain'
        scan_issue.issueDetail = 'foobar'
        scan_issue.issueName = 'test'
        scan_issue.url = 'https://syss.de'
        scan_issue.severity = 'High'

        return [scan_issue]

    def get_consolidated_issues_result(self, existing_issue, new_issue):
        return -1
