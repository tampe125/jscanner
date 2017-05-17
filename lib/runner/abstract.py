from abc import ABCMeta, abstractmethod

__author__ = 'Davide Tampellini'
__copyright__ = '2016-2017 Davide Tampellini - FabbricaBinaria'
__license__ = 'GNU GPL version 3 or later'


class AbstractCommand:
    __metaclass__ = ABCMeta

    def __init__(self, arguments):
        self.parentArgs = arguments

    @abstractmethod
    def run(self):
        pass

    def check(self):
        pass
