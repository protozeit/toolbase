import os, sys
from PIL import Image

''' Hexahue solver '''

class Color:
    """This class provides a color abstraction for each pixel in a valid hexahue image"""
    colors = []

    def __init__(self, r, g, b):
        self.r = r
        self.g = g
        self.b = b

        #Register the color
        Color.colors.append(self)

    def match(self, r, g, b):
        return self.r == r and self.g == g and self.b == b

    def get(r, g, b):
        """Return the associated color to these rgb values if it is a hexahue color, else None"""
        for color in Color.colors:
            if color.match(r, g, b):
                return color

        return None

#Register valid hexahue colors
BLUE = Color(0, 0, 255)
AZURE = Color(0, 255, 255)
PURPLE = Color(255, 0, 255)
RED = Color(255, 0, 0)
GREEN = Color(0, 255, 0)
YELLOW = Color(255, 255, 0)
WHITE = Color(255, 255, 255)
BLACK = Color(0, 0, 0)
GREY = Color(128, 128, 128)

#Maps pixel patterns to characters
#A pattern (A, B, C, D, E, F) corresponds to the following pixel configuration:
#
# AD
# BE
# CF
#
mapper = {(PURPLE, GREEN, BLUE, RED, YELLOW, AZURE):'A',
          (RED, GREEN, BLUE, PURPLE, YELLOW, AZURE):'B',
          (RED, PURPLE, BLUE, GREEN, YELLOW, AZURE):'C',
          (RED, YELLOW, BLUE, GREEN, PURPLE, AZURE):'D',
          (RED, YELLOW, PURPLE, GREEN, BLUE, AZURE):'E',
          (RED, YELLOW, AZURE, GREEN, BLUE, PURPLE):'F',
          (GREEN, YELLOW, AZURE, RED, BLUE, PURPLE):'G',
          (GREEN, RED, AZURE, YELLOW, BLUE, PURPLE):'H',
          (GREEN, BLUE, AZURE, YELLOW, RED, PURPLE):'I',
          (GREEN, BLUE, RED, YELLOW, AZURE, PURPLE):'J',
          (GREEN, BLUE, PURPLE, YELLOW, AZURE, RED):'K',
          (YELLOW, BLUE, PURPLE, GREEN, AZURE, RED):'L',
          (YELLOW, GREEN, PURPLE, BLUE, AZURE, RED):'M',
          (YELLOW, AZURE, PURPLE, BLUE, GREEN, RED):'N',
          (YELLOW, AZURE, GREEN, BLUE, PURPLE, RED):'O',
          (YELLOW, AZURE, RED, BLUE, PURPLE, GREEN):'P',
          (BLUE, AZURE, RED, YELLOW, PURPLE, GREEN):'Q',
          (BLUE, YELLOW, RED, AZURE, PURPLE, GREEN):'R',
          (BLUE, PURPLE, RED, AZURE, YELLOW, GREEN):'S',
          (BLUE, PURPLE, YELLOW, AZURE, RED, GREEN):'T',
          (BLUE, PURPLE, GREEN, AZURE, RED, YELLOW):'U',
          (AZURE, PURPLE, GREEN, BLUE, RED, YELLOW):'V',
          (AZURE, BLUE, GREEN, PURPLE, RED, YELLOW):'W',
          (AZURE, RED, GREEN, PURPLE, BLUE, YELLOW):'X',
          (AZURE, RED, BLUE, PURPLE, GREEN, YELLOW):'Y',
          (AZURE, RED, YELLOW, PURPLE, GREEN, BLUE):'Z',
          (BLACK, WHITE, BLACK, WHITE, BLACK, WHITE):'.',
          (WHITE, BLACK, WHITE, BLACK, WHITE, BLACK):',',
          (WHITE, WHITE, WHITE, WHITE, WHITE, WHITE):' ',
          (BLACK, BLACK, BLACK, BLACK, BLACK, BLACK):' ',
          (BLACK, WHITE, GREY, GREY, BLACK, WHITE):'0',
          (GREY, WHITE, GREY, BLACK, BLACK, WHITE):'1',
          (GREY, BLACK, GREY, WHITE, BLACK, WHITE):'2',
          (GREY, BLACK, BLACK, WHITE, GREY, WHITE):'3',
          (GREY, BLACK, WHITE, WHITE, GREY, BLACK):'4',
          (WHITE, BLACK, WHITE, GREY, GREY, BLACK):'5',
          (WHITE, GREY, WHITE, BLACK, GREY, BLACK):'6',
          (WHITE, GREY, GREY, BLACK, WHITE, BLACK):'7',
          (WHITE, GREY, BLACK, BLACK, WHITE, GREY):'8',
          (BLACK, GREY, BLACK, WHITE, WHITE, GREY):'9',
          }

class PixelMap:
    """This class reads pixels and associates them to a color pattern"""
    maps = []
    
    def __init__(self, x, y, image):
        #x and y are the coordinates of the top-left corner of a pixel pattern
        self.x = x
        self.y = y
        self.map = []

        for i in range(2):
            for j in range(3):
                self.map.append(Color.get(*image.getpixel((x + i, y + j))))

        #Turn self.map in a tuple in order to ensure it is a valid key in the mapper
        self.map = tuple(self.map)
        #Register the pixel map for later conversion
        PixelMap.maps.append(self)

    def convert():
        """Convert all registered pixel maps into text"""
        return ''.join(map(lambda pixel_map: mapper[pixel_map.map], PixelMap.maps))


if __name__ == '__main__':
    #Get path to hexahue file
    path = input('Path to hexahue file: ')
    #Get offsets [In the Houseplant CTF, offsets are 2/2/2/2]
    top, bottom, left, right = map(int, input('Border offsets (in pixels), with format TOP/BOTTOM/LEFT/RIGHT: ').split('/'))

    try:
        img = Image.open(path)
        img = img.convert('RGB') #Convert image to ensure proper rgb reading

        width, height = img.size
        #Making x the inner loop reads rows before columns [basically right -> left priority over top -> down]
        for y in range(top, height - bottom, 3): #A pattern's height is 3 pixels, so using a step of 3 goes to the next patterns row instead of the next pixels row
            for x in range(left, width - right, 2): #A pattern's width is 2 pixels
                PixelMap(x, y, img)

        #Return converted text
        print(PixelMap.convert())

    except IOError:
        print("Could not read %s" % path)
