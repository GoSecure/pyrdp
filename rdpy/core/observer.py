class Observer:
    """
    Base observer class used across RDPY.
    """
    def __init__(self, **kwargs):
        """
        Initialize a new Observer object.
        The kwargs are used to allow users to define custom handlers and pass them as arguments instead of inheriting from an observer class.
        This is useful in case of multiple inheritance, because only one method of the same name is preserved.
        """
        
        for (name, handler) in kwargs.items():
            if hasattr(self, name):
                setattr(self, name, handler)
            else:
                raise TypeError("Unexpected keyword argument '%s'" % name)