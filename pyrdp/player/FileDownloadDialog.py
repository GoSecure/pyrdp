#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
from PySide2.QtCore import QObject, Qt
from PySide2.QtGui import QCloseEvent
from PySide2.QtWidgets import QDialog, QLabel, QMessageBox, QProgressBar, QVBoxLayout


class FileDownloadDialog(QDialog):
    def __init__(self, remotePath: str, targetPath: str, parent: QObject):
        super().__init__(parent, Qt.CustomizeWindowHint | Qt.WindowTitleHint)
        self.titleLabel = QLabel(f"Downloading {remotePath} to {targetPath}")

        self.progressBar = QProgressBar()
        self.progressBar.setMinimum(0)
        self.progressBar.setMaximum(0)
        self.actualProgress = 0
        self.actualMaximum = 0
        self.isComplete = False

        self.progressLabel = QLabel("0 bytes")

        self.widgetLayout = QVBoxLayout()
        self.widgetLayout.addWidget(self.titleLabel)
        self.widgetLayout.addWidget(self.progressBar)
        self.widgetLayout.addWidget(self.progressLabel)

        self.setLayout(self.widgetLayout)
        self.setModal(True)

    def getHumanReadableSize(self, size: int):
        prefixes = ["", "K", "M", "G"]

        while len(prefixes) > 1:
            if size < 1024:
                break

            prefixes.pop(0)
            size /= 1024

        return f"{'%.2f' % size if size % 1 != 0 else int(size)} {prefixes[0]}"

    def updateProgress(self):
        progress = self.getHumanReadableSize(self.actualProgress)

        if self.actualMaximum > 0:
            percentage = int(self.actualProgress / self.actualMaximum * 100)
            maximum = self.getHumanReadableSize(self.actualMaximum)

            self.progressBar.setValue(percentage)
            self.progressLabel.setText(f"{progress}B / {maximum}B ({percentage}%)")
        else:
            self.progressBar.setValue(0)
            self.progressLabel.setText(f"{progress}B")

    def reportSize(self, maximum: int):
        self.actualMaximum = maximum

        if self.actualMaximum == 0:
            self.progressBar.setMaximum(0)
        else:
            self.progressBar.setMaximum(100)

        self.updateProgress()

    def reportProgress(self, progress: int):
        self.actualProgress = progress
        self.updateProgress()

    def reportCompletion(self, error: int):
        if error == 0:
            QMessageBox.information(self, "Download Complete", "Download completed successfully.")
        else:
            QMessageBox.critical(self, "Download Complete", f"Download failed. Error code: {'0x%08lx' % error}")

        self.isComplete = True
        self.close()

    def closeEvent(self, event: QCloseEvent):
        if not self.isComplete:
            event.ignore()