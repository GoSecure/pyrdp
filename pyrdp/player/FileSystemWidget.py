#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pathlib import Path
from typing import Optional

from PySide6.QtCore import QObject, QPoint, Qt, Signal
from PySide6.QtGui import QAction
from PySide6.QtWidgets import QFileDialog, QFrame, QLabel, QListWidget, QMenu, QMessageBox, QVBoxLayout, QWidget

from pyrdp.player.FileDownloadDialog import FileDownloadDialog
from pyrdp.player.filesystem import Directory, DirectoryObserver, File, FileSystemItemType
from pyrdp.player.FileSystemItem import FileSystemItem

import os

class FileSystemWidget(QWidget, DirectoryObserver):
    """
    Widget for listing directory contents and download files from the RDP client.
    """

    fileDownloadRequested = Signal(File, str, FileDownloadDialog)
    directoryDownloadRequested = Signal(Directory, str, FileDownloadDialog)

    def __init__(self, root: Directory, parent: QObject = None):
        """
        :param root: root of all directories. Directories in root will be displayed with drive icons.
        :param parent: parent object.
        """

        super().__init__(parent)
        self.root = root
        self.breadcrumbLabel = QLabel()

        self.titleLabel = QLabel()
        self.titleLabel.setStyleSheet("font-weight: bold")

        self.titleSeparator: QFrame = QFrame()
        self.titleSeparator.setFrameShape(QFrame.HLine)

        self.listWidget = QListWidget()
        self.listWidget.setSortingEnabled(True)
        self.listWidget.setContextMenuPolicy(Qt.CustomContextMenu)
        self.listWidget.customContextMenuRequested.connect(self.onCustomContextMenu)

        self.verticalLayout = QVBoxLayout()
        self.verticalLayout.addWidget(self.breadcrumbLabel)
        self.verticalLayout.addWidget(self.listWidget)

        self.setLayout(self.verticalLayout)
        self.listWidget.itemDoubleClicked.connect(self.onItemDoubleClicked)

        self.currentPath: Path = Path("/")
        self.currentDirectory: Directory = root
        self.listCurrentDirectory()

        self.currentDirectory.addObserver(self)

    def setWindowTitle(self, title: str):
        """
        Set the window title. When the title is not blank, a title label and a separator is displayed.
        :param title: the new title.
        """

        previousTitle = self.windowTitle()

        super().setWindowTitle(title)

        self.titleLabel.setText(title)

        if previousTitle == "" and title != "":
            self.verticalLayout.insertWidget(0, self.titleLabel)
            self.verticalLayout.insertWidget(1, self.titleSeparator)
        elif title == "" and previousTitle != "":
            self.verticalLayout.removeWidget(self.titleLabel)
            self.verticalLayout.removeWidget(self.titleSeparator)

            # noinspection PyTypeChecker
            self.titleLabel.setParent(None)

            # noinspection PyTypeChecker
            self.titleSeparator.setParent(None)

    def onItemDoubleClicked(self, item: FileSystemItem):
        """
        Handle double-clicks on items in the list. When the item is a directory, the current path changes and the
        contents of the directory are listed. Files are ignored.
        :param item: the item that was clicked.
        """

        if not item.isDirectory() and not item.isDrive():
            return

        if item.text() == "..":
            self.currentPath = self.currentPath.parent
        else:
            self.currentPath = self.currentPath / item.text()

        self.listCurrentDirectory()


    def listCurrentDirectory(self):
        """
        Refresh the list widget with the current directory's contents.
        """

        node = self.root

        for part in self.currentPath.parts[1 :]:
            node = next(d for d in node.directories if d.name == part)

        self.listWidget.clear()
        self.breadcrumbLabel.setText(f"Location: {str(self.currentPath)}")

        if node != self.root:
            self.listWidget.addItem(FileSystemItem("..", FileSystemItemType.Directory))

        for directory in node.directories:
            self.listWidget.addItem(FileSystemItem(directory.name, directory.type))

        for file in node.files:
            self.listWidget.addItem(FileSystemItem(file.name, file.type))

        if node is not self.currentDirectory:
            self.currentDirectory.removeObserver(self)
            node.addObserver(self)
            self.currentDirectory = node
            node.list()

    def onDirectoryChanged(self):
        """
        Refresh the directory view when the directory has changed.
        """

        self.listCurrentDirectory()

    def currentItemText(self) -> str:
        try:
            return self.listWidget.selectedItems()[0].text()
        except IndexError:
            return ""

    def selectedFile(self) -> Optional[File]:
        text = self.currentItemText()

        if text == "":
            return None

        if text == "..":
            return self.currentDirectory.parent

        for sequence in [self.currentDirectory.files, self.currentDirectory.directories]:
            for file in sequence:
                if text == file.name:
                    return file

        return None

    def canDownloadSelectedItem(self) -> bool:
        return self.selectedFile().type == FileSystemItemType.File

    def onCustomContextMenu(self, localPosition: QPoint):
        """
        Show a custom context menu with a "Download file" action when a file is right-clicked.
        :param localPosition: position where the user clicked.
        """
        selectedFile = self.selectedFile()

        if selectedFile is None:
            return

        globalPosition = self.listWidget.mapToGlobal(localPosition)

        downloadAction = QAction("Download file")
        downloadAction.setEnabled(selectedFile.type in [FileSystemItemType.File])
        downloadAction.triggered.connect(self.downloadFile)

        downloadRecursiveAction = QAction("Download files recursively")
        downloadRecursiveAction.setEnabled(selectedFile.type in [FileSystemItemType.Directory])
        downloadRecursiveAction.triggered.connect(self.downloadDirectoryRecursively)

        itemMenu = QMenu()
        itemMenu.addAction(downloadAction)
        itemMenu.addAction(downloadRecursiveAction)

        itemMenu.exec_(globalPosition)

    def downloadFile(self):
        file = self.selectedFile()

        if file.type != FileSystemItemType.File:
            return

        filePath = file.getFullPath()
        targetPath, _ = QFileDialog.getSaveFileName(self, f"Download file {filePath}", file.name)

        if targetPath == "":
            QMessageBox.critical(self, "Download file", "Please select a valid file. Aborting download.")
            return

        dialog = FileDownloadDialog(filePath, targetPath, False, self)
        dialog.incrementDownloadTotal()
        dialog.show()

        self.fileDownloadRequested.emit(file, targetPath, dialog)

    def downloadDirectoryRecursively(self):
        selectedFolder = self.selectedFile()

        if selectedFolder.type != FileSystemItemType.Directory:
            return

        directoryPath = QFileDialog.getExistingDirectory(self, f"Download folder {selectedFolder.getFullPath()}")
        remotePath = selectedFolder.getFullPath()

        dialog = None
        if directoryPath == "":
            QMessageBox.critical(self, "Download folder", f"Please select a valid folder. Aborting download.")
            return

        directoryPath += f"/{selectedFolder.name}"

        try:
            os.mkdir(directoryPath)
        except FileExistsError:
            QMessageBox.critical(self, "Download folder", f"Folder already exist. Make sure to select an empty directory. Aborting download.")
            return

        dialog = FileDownloadDialog(remotePath, directoryPath, True, self)
        dialog.show()

        self.directoryDownloadRequested.emit(selectedFolder, directoryPath, dialog)
