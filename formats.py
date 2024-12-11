from colorama import Fore, Back, Style

# Text color
BLACK = Fore.BLACK
RED = Fore.RED
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
BLUE = Fore.BLUE
MAGENTA = Fore.MAGENTA
CYAN = Fore.CYAN
WHITE = Fore.WHITE

# Background color
BLACK_BG = Back.BLACK
RED_BG = Back.RED
GREEN_BG = Back.GREEN
YELLOW_BG = Back.YELLOW
BLUE_BG = Back.BLUE
MAGENTA_BG = Back.MAGENTA
CYAN_BG = Back.CYAN
WHITE_BG = Back.WHITE

# Text style
RESET_ALL = Style.RESET_ALL
BRIGHT = Style.BRIGHT
DIM = Style.DIM
NORMAL = Style.NORMAL
RESET_DIM = f"{Style.RESET_ALL}{Style.NORMAL}"
BOLD = Style.BRIGHT
ITALIC = "\x1B[3m"  # ANSI escape code for italic text

