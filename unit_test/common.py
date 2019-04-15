import unittest
import logging
import sys
if sys.version_info[0] < 3:
    import mock
else:
    import unittest.mock as mock


test_logger = None


def get_test_logger(module_name):
    global test_logger
    if test_logger is None:
        logger = logging.getLogger(module_name)
        logger.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            '[%(asctime)s] [%(levelname)s] -> %(message)s'
        )
        handler = logging.FileHandler('logs/%s.log' % module_name, mode='w')
        handler.setFormatter(formatter)
        handler.setLevel(logging.DEBUG)
        logger.addHandler(handler)
        test_logger = logger
    return test_logger


def metaTest(func):
    def test_wrap(self):
        if self.__class__.__meta__:
            self.skipTest('Test should not run from meta class')
        else:
            return func(self)
    return test_wrap


class BaseTestCase(unittest.TestCase):
    def setUp(self):
        self.logger = get_test_logger(type(self).__module__)
        self.logger.info('TESTING METHOD: %s', self._testMethodName)
        self.todo = []
