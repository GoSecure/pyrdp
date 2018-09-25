class Subject(object):
    def __init__(self):
        self.observer = None
    
    def setObserver(self, observer):
        self.observer = observer