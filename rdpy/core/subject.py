class Subject:
    """
    Base class for objects that can have observers.
    """
    def __init__(self):
        self.observer = None
    
    def setObserver(self, observer):
        """
        Set this object's observer.
        :param observer: the observer.
        :type observer: rdpy.core.observer.Observer
        """
        self.observer = observer

def ObservedBy(ObserverClass):
    """
    This decorator adds a `createObserver` method to a class that creates an
    observer object and forwards all keyword arguments to its constructor.

    :param ObserverClass: The observer class.
    :type ObserverClass: type
    """
    def setCreateObserverMethod(SubjectClass):
        """
        Add a createObserver method to a class.
        :param SubjectClass: the subject class.
        :type SubjectClass: type
        :return: SubjectClass
        """

        def createObserver(self, **kwargs):
            """
            Creates a new observer by forwarding all keyword arguments to it.
            """
            observer = ObserverClass(**kwargs)
            self.setObserver(observer)
            return observer

        SubjectClass.createObserver = createObserver
        return SubjectClass
    
    return setCreateObserverMethod