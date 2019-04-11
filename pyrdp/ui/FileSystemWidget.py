from pathlib import Path

from PySide2.QtCore import QObject
from PySide2.QtWidgets import QWidget, QLabel, QListWidget, QVBoxLayout

from pyrdp.core import DirectoryObserver, Directory
from pyrdp.ui import FileSystemItem, FileSystemItemType


class FileSystemWidget(QWidget, DirectoryObserver):
    """
    Widget for display directories, using the pyrdp.core.filesystem classes.
    """

    def __init__(self, root: Directory, parent: QObject = None):
        """
        :param root: root of all directories. Directories in root will be displayed with drive icons.
        :param parent: parent object.
        """

        super().__init__(parent)
        self.root = root

        self.breadcrumbLabel = QLabel(str(Path("/").resolve()))
        self.listWidget = QListWidget()
        self.listWidget.setSortingEnabled(True)

        layout = QVBoxLayout()
        layout.addWidget(self.breadcrumbLabel)
        layout.addWidget(self.listWidget)

        self.setLayout(layout)
        self.listWidget.itemDoubleClicked.connect(self.onItemDoubleClicked)

        self.currentPath: Path = Path("/")
        self.currentDirectory: Directory = root
        self.listCurrentDirectory()

        self.currentDirectory.addObserver(self)

    def onItemDoubleClicked(self, item: FileSystemItem):
        """
        Handle double-clicks on items in the list.
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
            directories = node.getDirectories()
            node = next(d for d in directories if d.name == part)

        self.listWidget.clear()
        self.breadcrumbLabel.setText(str(self.currentPath))

        if node != self.root:
            self.listWidget.addItem(FileSystemItem("..", FileSystemItemType.Directory))

        for directory in node.getDirectories():
            itemType = FileSystemItemType.Drive if node == self.root else FileSystemItemType.Directory
            self.listWidget.addItem(FileSystemItem(directory.name, itemType))

        for file in node.getFiles():
            self.listWidget.addItem(FileSystemItem(file.name, FileSystemItemType.File))

        if node is not self.currentDirectory:
            self.currentDirectory.removeObserver(self)
            node.addObserver(self)
            self.currentDirectory = node

    def onDirectoryChanged(self, directory: 'Directory'):
        """
        Refresh the directory view when the directory has changed.
        :param directory: the directory that was changed.
        """

        self.listCurrentDirectory()