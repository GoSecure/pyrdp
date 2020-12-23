#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import hashlib
import tempfile
from logging import LoggerAdapter
from pathlib import Path
from typing import io


class FileMapping:
    """
    Class that maps a remote path to a local path. Used by the device redirection MITM component when it saves files
    transferred over RDP.
    """

    def __init__(self, file: io.BinaryIO, dataPath: Path, filesystemPath: Path, filesystemDir: Path, log: LoggerAdapter):
        """
        :param file: the file handle for dataPath
        :param dataPath: path where the file is actually saved
        :param filesystemPath: the path to the replicated filesystem, which will be symlinked to dataPath
        :param log: logger
        """
        self.file = file
        self.filesystemPath = filesystemPath
        self.dataPath = dataPath
        self.filesystemDir = filesystemDir
        self.log = log
        self.written = False

    def seek(self, offset: int):
        self.file.seek(offset)

    def write(self, data: bytes):
        self.file.write(data)
        self.written = True

    def getHash(self):
        with open(self.dataPath, "rb") as f:
            sha1 = hashlib.sha1()

            while True:
                buffer = f.read(65536)

                if len(buffer) == 0:
                    break

                sha1.update(buffer)

        return sha1.hexdigest()

    def finalize(self):
        self.log.debug("Closing file %(path)s", {"path": self.dataPath})
        self.file.close()

        fileHash = self.getHash()

        # Go up one directory because files are saved to outDir / tmp while we're downloading them
        hashPath = (self.dataPath.parents[1] / fileHash)

        # Don't keep the file if we haven't written anything to it or it's a duplicate, otherwise rename and move to files dir
        if not self.written or hashPath.exists():
            self.dataPath.unlink()
        else:
            self.dataPath = self.dataPath.rename(hashPath)

        # Whether it's a duplicate or a new file, we need to create a link to it in the filesystem clone
        if self.written:
            self.filesystemPath.parents[0].mkdir(exist_ok=True)

            if self.filesystemPath.exists():
                self.filesystemPath.unlink()

            self.filesystemPath.symlink_to(hashPath)

            self.log.info("SHA1 '%(path)s' = '%(hash)s'", {
                "path": self.filesystemPath.relative_to(self.filesystemDir), "hash": fileHash
            })

    @staticmethod
    def generate(remotePath: str, outDir: Path, filesystemDir: Path, log: LoggerAdapter):
        remotePath = Path(remotePath.replace("\\", "/"))
        filesystemPath = filesystemDir / remotePath.relative_to("/")

        tmpOutDir = outDir / "tmp"
        tmpOutDir.mkdir(exist_ok=True)

        handle, tmpPath = tempfile.mkstemp("", "", tmpOutDir)
        file = open(handle, "wb")

        log.info("Saving file '%(remotePath)s' to '%(localPath)s'", {
            "localPath": tmpPath, "remotePath": remotePath
        })

        return FileMapping(file, Path(tmpPath), filesystemPath, filesystemDir, log)
