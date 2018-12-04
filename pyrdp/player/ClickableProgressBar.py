from PyQt4.QtGui import QWidget, QProgressBar, QMouseEvent


class ClickableProgressBar(QProgressBar):
    """
    Progress bar widget that can be clicked to set the current progress.
    """

    def __init__(self, parent: QWidget = None):
        super().__init__(parent)
        self.setTextVisible(False)

    def setValue(self, p_int):
        QProgressBar.setValue(self, p_int)
        self.repaint()

    def mousePressEvent(self, event: QMouseEvent):
        progress = event.x() / self.width()
        value = int(progress * self.maximum())
        self.setValue(value)