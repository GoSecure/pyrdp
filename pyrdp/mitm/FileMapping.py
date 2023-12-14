#
# This file is part of the PyRDP project.
# Copyright (C) 2019-2022 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import hashlib
import os
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
        # only available once finalized (since we hash to find the name we can't know ahead of time)
        self.fileHash: str = None

    def seek(self, offset: int):
        if not self.file.closed:
            self.file.seek(offset)

    def write(self, data: bytes):
        self.file.write(data)
        self.written = True

    def _getShaHash(self):
        with open(self.dataPath, "rb") as f:
            # Note: In early 2022 we switched to sha256 for file hashes. If you
            #       want to use sha1, uncomment the next line and comment the
            #       other one below.
            #hash = hashlib.sha1()
            hash = hashlib.sha256()

            while True:
                buffer = f.read(65536)

                if len(buffer) == 0:
                    break

                hash.update(buffer)

        return hash.hexdigest()

    def finalize(self):
        if self.file.closed:
            return

        self.log.debug("Closing file %(path)s", {"path": self.dataPath})
        self.file.close()

        self.fileHash = self._getShaHash()

        # Go up one directory because files are saved to outDir / tmp while we're downloading them
        hashPath = (self.dataPath.parents[1] / self.fileHash)

        # Don't keep the file if we haven't written anything to it or it's a duplicate, otherwise rename and move to files dir
        if not self.written or hashPath.exists():
            self.dataPath.unlink()
        else:
            self.dataPath = self.dataPath.rename(hashPath)

        # Whether it's a duplicate or a new file, we need to create a link to it in the filesystem clone
        if self.written:
            self.filesystemPath.parents[0].mkdir(exist_ok=True, parents=True)

            if self.filesystemPath.exists():
                self.filesystemPath.unlink()

            # Make the symlink relative so you can move the output folder around and it will still work.
            self.filesystemPath.symlink_to(Path(os.path.relpath(hashPath, self.filesystemPath.parent)))

            self.log.info("SHA-256 '%(path)s' = '%(shasum)s'", {
                "path": str(self.filesystemPath.relative_to(self.filesystemDir)), "shasum": self.fileHash
            })

    def onDisconnection(self, reason):
        if not self.file.closed:
            self.log.info("Got disconnected with an active file mapping. Path: '%(path)s'. "
                          "Non-zero partial file transfer is kept here: '%(dataPath)s'. Closing.",
                          {"path": str(self.filesystemPath.relative_to(self.filesystemDir)), "dataPath": str(self.dataPath)})
            self.file.close()
            if not self.written:
                self.dataPath.unlink(missing_ok=True)

    @staticmethod
    def generate(remotePath: str, outDir: Path, filesystemDir: Path, log: LoggerAdapter):
        remotePath = Path(remotePath.replace("\\", "/"))
        filesystemPath = filesystemDir / remotePath.relative_to("/")

        tmpOutDir = outDir / "tmp"
        tmpOutDir.mkdir(exist_ok=True)

        handle, tmpPath = tempfile.mkstemp("", "", tmpOutDir)
        file = open(handle, "wb")

        log.info("Saving file '%(remotePath)s' to '%(localPath)s'", {
            "localPath": str(tmpPath), "remotePath": str(remotePath)
        })

        return FileMapping(file, Path(tmpPath), filesystemPath, filesystemDir, log)
