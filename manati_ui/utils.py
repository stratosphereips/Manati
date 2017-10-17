import linecache
import sys
import logging


# Get an instance of a logger
logger = logging.getLogger(__name__)


def print_exception():
    logger.error(str(sys.exc_info()))
    exc_type, exc_obj, tb = sys.exc_info()
    f = tb.tb_frame
    lineno = tb.tb_lineno
    filename = f.f_code.co_filename
    linecache.checkcache(filename)
    line = linecache.getline(filename, lineno, f.f_globals)
    error = 'EXCEPTION IN ({}, LINE {} "{}"): {}'.format(filename, lineno, line.strip(), exc_obj)
    print(error)
    return error