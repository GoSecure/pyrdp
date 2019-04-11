#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from enum import Enum

from PySide2.QtCore import QObject
from PySide2.QtWidgets import QListWidgetItem, QFileIconProvider


class FileSystemItemType(Enum):
        Directory = QFileIconProvider.IconType.Folder
        Drive = QFileIconProvider.IconType.Drive
        File = QFileIconProvider.IconType.File

class FileSystemItem(QListWidgetItem):
    def __init__(self, name: str, itemType: FileSystemItemType, parent: QObject = None):
        icon = QFileIconProvider().icon(itemType.value)

        super().__init__(icon, name, parent)
        self.itemType = itemType

    def isDirectory(self) -> bool:
        return self.itemType == FileSystemItemType.Directory

    def isDrive(self) -> bool:
        return self.itemType == FileSystemItemType.Drive

    def isFile(self) -> bool:
        return self.itemType == FileSystemItemType.File

    def __lt__(self, other: 'FileSystemItem'):
        if self.text() == ".." and self.isDirectory():
            return True

        if self.isDrive() != other.isDrive():
            return self.isDrive()

        if self.isDirectory() != other.isDirectory():
            return self.isDirectory()

        return self.text() < other.text()