#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from typing import List

from pyrdp.core.observer import Observer
from pyrdp.core.subject import ObservedBy, Subject


class File:
    """
    Class representing a file on a filesystem. It doesn't have to exist, it is merely a representation of a file.
    """

    def __init__(self, name: str):
        """
        :param name: the name of the file, without any directory.
        """
        self.name = name


class DirectoryObserver(Observer):
    """
    Observer class for watching directory changes.
    """

    def onDirectoryChanged(self, directory: 'Directory'):
        """
        Notification for directory changes.
        :param directory: the directory that was changed.
        """
        pass


@ObservedBy(DirectoryObserver)
class Directory(Subject):
    """
    Class representing a directory on a filesystem. It doesn't have to exist, it is merely a representation of a directory.
    """

    def __init__(self, name: str):
        """
        :param name: the name of the directory, without any other directory.
        """

        super().__init__()

        self.name = name
        self.directories: List['Directory'] = []
        self.files: List[File] = []

    def getDirectories(self) -> List['Directory']:
        return list(self.directories)

    def getFiles(self) -> List[File]:
        return list(self.files)

    def addDirectory(self, name: str) -> 'Directory':
        """
        :param name: name of the directory to add.
        """

        directory = Directory(name)
        self.directories.append(directory)

        self.observer.onDirectoryChanged(self)

        return directory

    def addFile(self, name: str) -> File:
        """
        :param name: name of the file to add.
        """

        file = File(name)
        self.files.append(file)

        self.observer.onDirectoryChanged(self)

        return file