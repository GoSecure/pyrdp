from pathlib import Path
from typing import BinaryIO

from pyrdp.core.observer import Observer
from pyrdp.core.subject import ObservedBy, Subject


class FileProxyObserver(Observer):
    def onFileCreated(self, fileProxy: 'FileProxy'):
        pass

    def onFileClosed(self, fileProxy: 'FileProxy'):
        pass


@ObservedBy(FileProxyObserver)
class FileProxy(Subject):
    """
    Proxy object that waits until a file is accessed before creating it.
    """

    def __init__(self, path: Path, mode: str):
        """
        :param path: path of the file
        :param mode: file opening mode
        """
        super().__init__()

        self.path = path
        self.mode = mode
        self.file: BinaryIO = None

    def createFile(self):
        """
        Create the file and overwrite this object's methods with the file object's methods.
        """

        if self.file is None:
            self.file = open(str(self.path), self.mode)
            self.write = self.file.write
            self.seek = self.file.seek
            self.close = self.file.close

            self.observer.onFileCreated(self)

    def write(self, *args, **kwargs):
        self.createFile()
        self.file.write(*args, **kwargs)

    def seek(self, *args, **kwargs):
        self.createFile()
        self.file.seek(*args, **kwargs)

    def close(self):
        if self.file is not None:
            self.file.close()
            self.observer.onFileClosed(self)