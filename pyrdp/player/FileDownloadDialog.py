#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
from PySide6.QtCore import QObject, Qt
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import QDialog, QLabel, QMessageBox, QProgressBar, QPushButton, QVBoxLayout


class FileDownloadDialog(QDialog):
    def __init__(self, remotePath: str, targetPath: str, isMultipleDownload: bool, parent: QObject):
        super().__init__(parent, Qt.CustomizeWindowHint | Qt.WindowTitleHint)
        self.titleLabel = QLabel(f"Downloading {remotePath} to {targetPath}")

        self.progressBar = QProgressBar()
        self.progressBar.setMinimum(0)
        self.progressBar.setMaximum(0)


        self.actualProgress = 0
        self.actualMaximum = 0
        self.isComplete = False

        self.isMultipleDownload = isMultipleDownload
        self.downloadCount = 0
        self.downloadTotal = 0

        self.progressLabel = QLabel(f"{self.downloadCount} / {self.downloadTotal} files downloaded")
        self.progressSizeLabel = QLabel("0 bytes")

        self.widgetLayout = QVBoxLayout()
        self.widgetLayout.addWidget(self.titleLabel)
        self.widgetLayout.addWidget(self.progressLabel)
        self.widgetLayout.addWidget(self.progressBar)
        self.widgetLayout.addWidget(self.progressSizeLabel)

        self.closeButton = QPushButton("Continue download in background")
        self.closeButton.clicked.connect(self.hide)
        self.widgetLayout.addWidget(self.closeButton)

        self.setLayout(self.widgetLayout)

    def getHumanReadableSize(self, size: int):
        prefixes = ["", "K", "M", "G"]

        while len(prefixes) > 1:
            if size < 1024:
                break

            prefixes.pop(0)
            size /= 1024

        return f"{'%.2f' % size if size % 1 != 0 else int(size)} {prefixes[0]}"

    def incrementDownloadCount(self):
        self.downloadCount += 1
        self.progressLabel.setText(f"{self.downloadCount} / {self.downloadTotal} files downloaded")

    def incrementDownloadTotal(self):
        self.downloadTotal += 1
        self.progressLabel.setText(f"{self.downloadCount} / {self.downloadTotal} files downloaded")

    def updateProgress(self):
        progress = self.getHumanReadableSize(self.actualProgress)

        if self.actualMaximum > 0:
            percentage = int(self.actualProgress / self.actualMaximum * 100)
            maximum = self.getHumanReadableSize(self.actualMaximum)

            self.progressBar.setValue(percentage)
            self.progressSizeLabel.setText(f"{progress}B / {maximum}B ({percentage}%)")
        else:
            self.progressBar.setValue(0)
            self.progressSizeLabel.setText(f"{progress}B")

    def reportSize(self, maximum: int):
        self.actualMaximum = maximum

        if self.actualMaximum == 0:
            self.progressBar.setMaximum(0)
        else:
            self.progressBar.setMaximum(100)

        self.updateProgress()

    def reportProgress(self, progress: int):
        self.actualProgress += progress
        self.updateProgress()

    def reportCompletion(self, error: int):
        self.show()

        # QMessageBox is a modal, meaning that execution of code stops until the window closes
        # We need our own message box if we want to queue multiple downloads
        box = QMessageBox(self)
        box.setWindowTitle("Download Complete")
        box.setWindowModality(Qt.NonModal)

        if error == 0:
            box.setIcon(QMessageBox.Information)
            box.setText("Download completed successfully.")
        else:
            box.setIcon(QMessageBox.Critical)
            box.setText(f"Download failed. Error code: {'0x%08lx' % error}")

        box.show()
        self.isComplete = True
        self.close()

    def closeEvent(self, event: QCloseEvent):
        if not self.isComplete:
            event.ignore()
