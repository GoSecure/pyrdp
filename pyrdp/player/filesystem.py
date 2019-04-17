#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from enum import IntEnum
from pathlib import PosixPath
from typing import List

from pyrdp.core import ObservedBy, Observer, Subject


class FileSystemItemType(IntEnum):
    Directory = 1
    Drive = 2
    File = 3


class FileSystemItem:
    def __init__(self, name: str, itemType: FileSystemItemType):
        super().__init__()
        self.name = name
        self.type = itemType


class DirectoryObserver(Observer):
    def onDirectoryChanged(self):
        pass

    def onListDirectory(self, deviceID: int, path: str):
        pass

@ObservedBy(DirectoryObserver)
class Directory(FileSystemItem, Subject):
    def __init__(self, name: str, parent: 'Directory' = None):
        super().__init__(name, FileSystemItemType.Directory)
        self.parent = parent
        self.files: List[File] = []
        self.directories: List[Directory] = []

    def addFile(self, name: str):
        file = File(name, self)
        self.files.append(file)

        self.observer.onDirectoryChanged()

        return file

    def addDirectory(self, name: str):
        directory = Directory(name, self)
        self.directories.append(directory)

        self.observer.onDirectoryChanged()

        return directory

    def list(self, name: str = ""):
        if self.parent is None:
            return

        path = PosixPath(self.name)

        if name != "":
            path /= name
        else:
            self.files.clear()
            self.directories.clear()

        self.parent.list(str(path))


class File(FileSystemItem):
    def __init__(self, name: str, parent: Directory):
        super().__init__(name, FileSystemItemType.File)
        self.name = name
        self.parent = parent


class Drive(Directory):
    def __init__(self, name: str, deviceID: int):
        super().__init__(name, None)
        self.type = FileSystemItemType.Drive
        self.deviceID = deviceID

    def list(self, name: str = ""):
        path = "/"

        if name != "":
            path += name
        else:
            self.files.clear()
            self.directories.clear()

        self.observer.onListDirectory(self.deviceID, path)


@ObservedBy(DirectoryObserver)
class FileSystem(Directory):
    def __init__(self):
        super().__init__("")

    def addDrive(self, name: str, deviceID: int) -> Drive:
        drive = Drive(name, deviceID)
        self.directories.append(drive)

        self.observer.onDirectoryChanged()

        return drive

    def list(self, name: str = ""):
        pass