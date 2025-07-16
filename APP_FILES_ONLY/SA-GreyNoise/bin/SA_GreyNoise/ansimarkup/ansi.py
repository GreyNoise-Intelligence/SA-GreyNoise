from colorama import Back, Fore, Style
from colorama.ansi import AnsiCodes


class AnsiExtendedStyle(AnsiCodes):
    ITALIC = 3
    UNDERLINE = 4
    BLINK = 5
    REVERSE = 7
    HIDE = 8
    STRIKE = 9


ExtendedStyle = AnsiExtendedStyle()
