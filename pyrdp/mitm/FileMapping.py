import datetime
import json
from pathlib import Path
from typing import Dict

import names


class FileMapping:
    """
    Class that maps a remote path to a local path. Used by the device redirection MITM component when it saves files
    transferred over RDP.
    """

    def __init__(self, remotePath: Path, localPath: Path, creationTime: datetime.datetime, fileHash: str):
        """
        :param remotePath: the path of the file on the original machine
        :param localPath: the path of the file on the intercepting machine
        :param creationTime: the creation time of the local file
        :param fileHash: the file hash in hex format (empty string if the file is not complete)
        """
        self.remotePath = remotePath
        self.localPath = localPath
        self.creationTime = creationTime
        self.hash: str = fileHash

    @staticmethod
    def generate(remotePath: Path, outDir: Path):
        localName = f"{names.get_first_name()}{names.get_last_name()}"
        creationTime = datetime.datetime.now()

        index = 2
        suffix = ""

        while True:
            if not (outDir / f"{localName}{suffix}").exists():
                break
            else:
                suffix = f"_{index}"
                index += 1

        localName += suffix

        return FileMapping(remotePath, outDir / localName, creationTime, "")


class FileMappingEncoder(json.JSONEncoder):
    """
    JSON encoder for FileMapping objects.
    """

    def default(self, o):
        if isinstance(o, datetime.datetime):
            return o.isoformat()
        elif not isinstance(o, FileMapping):
            return super().default(o)

        return {
            "remotePath": str(o.remotePath),
            "localPath": str(o.localPath),
            "creationTime": o.creationTime,
            "sha1": o.hash
        }


class FileMappingDecoder(json.JSONDecoder):
    """
    JSON decoder for FileMapping objects.
    """

    def __init__(self):
        super().__init__(object_hook=self.decodeFileMapping)

    def decodeFileMapping(self, dct: Dict):
        for key in ["remotePath", "localPath", "creationTime"]:
            if key not in dct:
                return dct

        creationTime = datetime.datetime.strptime(dct["creationTime"], "%Y-%m-%dT%H:%M:%S.%f")
        return FileMapping(Path(dct["remotePath"]), Path(dct["localPath"]), creationTime, dct["sha1"])