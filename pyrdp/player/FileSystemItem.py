#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
from typing import Dict

from PySide6.QtCore import QObject
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QFileIconProvider, QListWidgetItem

from pyrdp.player.filesystem import FileSystemItemType


class FileSystemItem(QListWidgetItem):
    _iconCache: Dict[QFileIconProvider.IconType, QIcon] = {}

    def __init__(self, name: str, itemType: FileSystemItemType, parent: QObject = None):
        if itemType == FileSystemItemType.Drive:
            iconType = QFileIconProvider.IconType.Drive
        elif itemType == FileSystemItemType.Directory:
            iconType = QFileIconProvider.IconType.Folder
        else:
            iconType = QFileIconProvider.IconType.File

        icon = FileSystemItem._iconCache.get(iconType, None)

        if icon is None:
            icon = QFileIconProvider().icon(iconType)
            FileSystemItem._iconCache[iconType] = icon

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

        return self.text().upper() < other.text().upper()
