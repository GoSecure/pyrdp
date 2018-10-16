class RDPClientInfoPDU:
    def __init__(self, codePage, flags, domain, username, password, alternateShell, workingDir, extraInfo):
        self.codePage = codePage
        self.flags = flags
        self.domain = domain
        self.username = username
        self.password = password
        self.alternateShell = alternateShell
        self.workingDir = workingDir
        self.extraInfo = extraInfo

