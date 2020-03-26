#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pathlib import Path
from typing import Optional


class MITMConfig:
    """
    Configuration options for the RDP MITM.
    """

    def __init__(self):
        self.targetHost: str = None
        """The RDP server"""

        self.targetPort: int = None
        """The RDP server's port"""

        self.certificateFileName: str = None
        """Path to the TLS certificate"""

        self.privateKeyFileName: str = None
        """Path to the TLS private key"""

        self.attackerHost: Optional[str] = None
        """The attacker host"""

        self.attackerPort: Optional[int] = None
        """The attacker port"""

        self.replacementUsername: str = None
        """The replacement username for login attempts"""

        self.replacementPassword: str = None
        """The replacement password for login attempts"""

        self.outDir: Path = None
        """The output directory"""

        self.extractFiles: bool = True
        """Whether to extract file transferred between the client and server."""

        self.recordReplays: bool = True
        """Whether replays should be recorded or not"""

        self.downgrade: bool = True
        """Whether to actively downgrade unsupported extensions."""

        self.payload: str = ""
        """Payload to send automatically upon connection"""

        self.payloadDelay: int = None
        """Delay before sending payload automatically, in milliseconds"""

        self.payloadDuration: int = None
        """Amount of time the payload should take to complete, in milliseconds"""

        self.enableCrawler: bool = False
        """Whether the crawler should be enabled or not"""

        self.crawlerMatchFileName: str = None
        """Path to the crawler match configuration file"""

        self.crawlerIgnoreFileName: str = None
        """Path to the crawler ignore configuration file"""

        self.disableActiveClipboardStealing: bool = False
        """ If set to False, use PassiveClipboardStealer instead of ActiveClipboardStealer."""

    @property
    def replayDir(self) -> Path:
        """
        Get the directory for replay files.
        """
        return self.outDir / "replays"

    @property
    def fileDir(self) -> Path:
        """
        Get the directory for intercepted files.
        """
        return self.outDir / "files"
