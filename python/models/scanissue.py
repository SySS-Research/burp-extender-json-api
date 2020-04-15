

class ScanIssue:

    def __init__(self):
        # "Certain", "Firm", "Tentative"
        self.confidence = ''
        # disabled for now
        # self.httpMessages = []
        # disabled for now
        # self.httpService = None
        # background description
        self.issueBackground = ''
        # issue details
        self.issueDetail = ''
        # issue name
        self.issueName = ''
        # https://portswigger.net/kb/issues
        # 0x08000000 = Extension generated issue
        self.issueType = 0x08000000
        # background description for remediation
        self.remediationBackground = ''
        # remediation details
        self.remediationDetail = ''
        # High", "Medium", "Low", "Information", "False positive"
        self.severity = ''
        # "https://example.org/foo"
        self.url = ''

    def get_data(self):
        return self.__dict__
