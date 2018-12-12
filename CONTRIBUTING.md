# Contributing to PyRDP
## Contribution Guidelines

1. Check if there is an issue for what you want to contribute:

    1.1. If there is no issue, please create one explaining what should be done.
    
    1.2. If there is already an issue, consider adding a comment saying that you're working on it. 
    
2. Document your methods and classes with docstrings using the reStructuredText syntax.
3. Coding style is mostly PEP8-based with the following exceptions:
    
    3.1. Use the camel case naming convention.
    
    3.2. Limit your lines to 120 characters. There can be exceptions, just make sure the code is readable.

4. Use Python 3 type hinting whenever possible.

    4.1. If you come across reStructuredText type hinting, please change it to Python 3 type hinting:
    ```python
    # reStructuredText type hinting
    def myFunction(param1):
        """
        :type param1: str
        """
    
    # Python 3 type hinting (preferred)
    def myFunction(param1: str):
        pass
    ```
    
5. Use [f-strings](https://www.python.org/dev/peps/pep-0498/) or
[str.format()](https://docs.python.org/3/library/stdtypes.html#str.format) for formatting. For example:

    ```python
    who = "World"
    print(f"Hello {who}!")
    print("Hello {}!".format(who))
    ```

    5.1. For log statements, use %-style formatting:
    ```python
    who = "World"
    logging.info("Hello %(who)s!", {"who": "World"})
    ```
    
    This separates variables from the message, which can be helpful for analysis purposes.