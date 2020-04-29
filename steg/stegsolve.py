#!/usr/bin/env python

''' Dumps every plane of every channel of an image as a seperate png '''

from PIL import Image
from string import printable
from itertools import groupby

img = Image.open("image.png")

def get_plane(img, channel, index=0):
    if channel in img.mode:
        new_image = Image.new('1', img.size)
        new_image_data = new_image.load()
        img_data = img.load()

        channel_index = img.mode.index(channel)

        for x in range(img.size[0]):
            for y in range(img.size[1]):
                color = img_data[x, y]
                channel = color[channel_index]
                plane = bin(channel)[2:].zfill(8)

                try:
                    new_image_data[x, y] = 255 * int(plane[abs(index-7)])
                except IndexError:
                    pass
        return new_image

for channel in 'RGB':
    for plane in range(8):
        x = get_plane(img, channel, plane)
        x.save(f'{channel}-{plane}.png')
