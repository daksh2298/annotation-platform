from .symbols import INFO, DEBUG, WARN, ERROR


class Logger(object):
    @staticmethod
    def info(message=''):
        print(INFO + " " + message)

    @staticmethod
    def debug(message=''):
        print(DEBUG + " " + message)

    @staticmethod
    def warn(message=''):
        print(WARN + " " + message)

    @staticmethod
    def error(message=''):
        print(ERROR + " " + message)

    @staticmethod
    def i(message=""):
        Logger.info(message)

    @staticmethod
    def d(message=""):
        Logger.debug(message)

    @staticmethod
    def w(message=""):
        Logger.warn(message)

    @staticmethod
    def e(message=""):
        Logger.error(message)
