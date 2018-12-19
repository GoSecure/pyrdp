#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from PyQt4.QtGui import QPushButton, QWidget, QIcon


class PlayPauseButton(QPushButton):
    """
    Button that switches between "play" and "pause" depending on its state.
    """

    def __init__(self, parent: QWidget = None, playText = "Play", pauseText = "Pause"):
        super().__init__(parent)
        self.clicked.connect(self.onClick)
        self.playText = playText
        self.pauseText = pauseText
        self.playing = False
        self.setPlaying(self.playing)

    def onClick(self):
        self.setPlaying(not self.playing)

    def setPlaying(self, playing):
        self.playing = playing

        if self.playing:
            self.setText(self.pauseText)
            self.setIcon(QIcon.fromTheme("media-playback-pause"))
        else:
            self.setText(self.playText)
            self.setIcon(QIcon.fromTheme("media-playback-start"))