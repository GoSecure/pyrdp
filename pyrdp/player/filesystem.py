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

    def getFullPath(self, name: str = "") -> str:
        pass


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
        if name == "":
            self.files.clear()
            self.directories.clear()

        path = self.getFullPath(name)
        self.parent.list(str(path))

    def getFullPath(self, name: str = "") -> str:
        path = PosixPath(self.name)

        if name != "":
            path /= name

        path = str(path)

        if self.parent is None:
            return path
        else:
            return self.parent.getFullPath(path)

    def getRootParent(self) -> FileSystemItem:
        parent = self.parent

        while parent.parent is not None:
            parent = parent.parent

        return parent

class File(FileSystemItem):
    def __init__(self, name: str, parent: Directory):
        super().__init__(name, FileSystemItemType.File)
        self.parent = parent

    def getFullPath(self, name: str = "") -> str:
        path = PosixPath(self.name)

        if name != "":
            path /= name

        path = str(path)

        if self.parent is None:
            return path
        else:
            return self.parent.getFullPath(path)

    def getRootParent(self) -> FileSystemItem:
        parent = self.parent

        while parent.parent is not None:
            parent = parent.parent

        return parent

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

    def getFullPath(self, name: str = "") -> str:
        path = PosixPath("/")

        if name != "":
            path /= name

        return str(path)

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