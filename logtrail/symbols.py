# coding=utf-8
from .colors import COLORS
from .compatible import uchr

TRAIL = uchr(57520)

INFO = \
    COLORS["BG"]['INFO'] + COLORS["FG"]['INFO'] + \
    " INFO  " + \
    COLORS['RESET'] + COLORS["TRAIL"]['INFO'] + \
    TRAIL + \
    COLORS['RESET']
DEBUG = \
    COLORS["BG"]['DEBUG'] + COLORS["FG"]['DEBUG'] + \
    " DEBUG " + \
    COLORS['RESET'] + COLORS["TRAIL"]['DEBUG'] + \
    TRAIL + \
    COLORS['RESET']
WARN = \
    COLORS["BG"]['WARN'] + COLORS["FG"]['WARN'] + \
    " WARN  " + \
    COLORS['RESET'] + COLORS["TRAIL"]['WARN'] + \
    TRAIL + \
    COLORS['RESET']
ERROR = \
    COLORS["BG"]['ERROR'] + COLORS["FG"]['ERROR'] + \
    " ERROR " + \
    COLORS['RESET'] + COLORS["TRAIL"]['ERROR'] + \
    TRAIL + \
    COLORS['RESET']
