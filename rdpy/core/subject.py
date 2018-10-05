class Subject(object):
    """
    Base class for objects that can have observers.
    """
    def __init__(self):
        self.observer = None
    
    def setObserver(self, observer):
        """
        Set this object's observer.
        :param observer: the observer.
        """
        self.observer = observer

def ObservedBy(ObserverClass):
    """
    This decorator adds a `createObserver` method to a class that creates an
    observer object and forwards all kwargs to its constructor.

    :param ObserverClass: The observer class.
    """
    def setCreateObserverMethod(SubjectClass):
        def createObserver(self, **kwargs):
            self.setObserver(ObserverClass(**kwargs))
        SubjectClass.createObserver = createObserver
        return SubjectClass
    
    return setCreateObserverMethod