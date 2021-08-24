# This file is part of the PyRDP project.
#
# Copyright (C) 2021 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

class ImageHandler:
    def notifyImage(self, x: int, y: int, img: 'QImage', width: int, height: int):
        raise NotImplementedError("ImageHandler.notifyImage is not implemented.")

    def resize(self, width: int, height: int):
        raise NotImplementedError("ImageHandler.resize is not implemented.")

    def update(self) -> int:
        raise NotImplementedError("ImageHandler.update is not implemented")

    @property
    def screen(self) -> 'QImage':
        raise NotImplementedError("ImageHandler.screen is not implemented")
