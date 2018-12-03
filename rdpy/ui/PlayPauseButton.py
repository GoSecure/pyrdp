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
        self.setText(self.playText)

    def onClick(self):
        self.playing = not self.playing

        if self.playing:
            self.setText(self.pauseText)
            self.setIcon(QIcon.fromTheme("media-playback-pause"))
        else:
            self.setText(self.playText)
            self.setIcon(QIcon.fromTheme("media-playback-play"))