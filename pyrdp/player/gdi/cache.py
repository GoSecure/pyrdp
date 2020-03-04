#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

"""
GDI Cache Management Layer.
"""

from PySide2.QtCore import QSize
from PySide2.QtGui import QBrush, QImage, QBitmap

from pyrdp.parser.rdp.orders.common import Glyph


class BitmapCache:
    """Bitmap cache."""

    def __init__(self, persist=False):
        self.caches = {}
        self.persist = persist
        if persist:
            raise Exception('Persistent cache is not supported yet.')

    def has(self, cid: int, idx: int) -> bool:
        """
        Check whether a cache contains an entry.

        :param cid: The cache id to use.
        :param idx: The cache entry index.

        :returns: True if (cid:idx) is in the cache, false otherwise.
        """
        if cid not in self.caches:
            return False
        cache = self.caches[cid]
        return idx in cache

    def get(self, cid: int, idx: int) -> QImage:
        """
        Retrieve an entry from the cache.

        :param cid: The cache id to use.
        :param idx: The cache entry index.

        :returns: The cache entry or None if it does not exist.
        """
        if cid not in self.caches:
            return None
        cache = self.caches[cid]
        if idx not in cache:
            return None
        return cache[idx]

    def add(self, cid: int, idx: int, entry: QImage) -> bool:
        """
        Add an entry to the cache.

        :returns: True if the entry is a fresh entry, False if it replaced an existing one.
        """
        if cid not in self.caches:
            self.caches[cid] = {}
        cache = self.caches[cid]
        cache[idx] = entry

    def evict(self, cid: int, idx: int) -> bool:
        """
        Evict an entry from the cache.

        :param cid: The cache id to use.
        :param idx: The cache entry index.

        :returns: True if an entry was evicted, false otherwise.
        """
        if not self.has(cid, idx):
            return False
        del self.caches[cid][idx]


class BrushCache:
    """Brush cache."""

    def __init__(self):
        self.entries = {}

    def has(self, idx: int) -> bool:
        return idx in self.entries

    def get(self, idx: int) -> QBrush:
        if idx in self.entries:
            return self.entries[idx]
        else:
            return None

    def add(self, idx: int, b: QBrush):
        self.entries[idx] = b


class PaletteCache:
    """ColorTable cache."""

    def __init__(self):
        self.entries = {}

    def has(self, idx: int) -> bool:
        return idx in self.entries

    def get(self, idx: int) -> [int]:
        if idx in self.entries:
            return self.entries[idx]
        else:
            return None

    def add(self, idx: int, colors: [int]):
        self.entries[idx] = colors


class NineGridCache:
    """NineGrid bitmap cache."""

    def __init__(self):
        self.entries = {}

    def has(self, idx: int) -> bool:
        return idx in self.entries

    def get(self, idx: int) -> QImage:
        if idx in self.entries:
            return self.entries[idx]
        else:
            return None

    def add(self, idx: int, bmp: QImage):
        self.entries[idx] = bmp


class GlyphEntry:
    """Glyph cache entry."""

    def __init__(self, glyph: Glyph):
        """Construct a cache entry from a glyph."""

        # Glyph origin.
        self.x = glyph.x
        self.y = glyph.y
        self.w = glyph.w
        self.h = glyph.h

        self.bitmap = QBitmap.fromData(QSize(self.w, self.h), glyph.data, QImage.Format_Mono)


class GlyphCache:
    """Glyph cache."""

    def __init__(self):
        self.caches = {}
        self.fragments = {}

    def get(self, cid: int, idx: int) -> GlyphEntry:
        """
        Retrieve an entry from the cache.

        :param cid: The cache id to use.
        :param idx: The cache entry index.

        :returns: The cache entry or None if it does not exist.
        """
        if cid not in self.caches:
            return None
        cache = self.caches[cid]
        if idx not in cache:
            return None
        return cache[idx]

    def add(self, cid: int, idx: int, entry: GlyphEntry) -> bool:
        """
        Add an entry to the cache.

        :returns: True if the entry is a fresh entry, False if it replaced an existing one.
        """
        if cid not in self.caches:
            self.caches[cid] = {}
        cache = self.caches[cid]
        cache[idx] = entry

    def getFragment(self, cid: int, fid: int) -> bytes:
        """Get a glyph fragment."""
        if cid not in self.fragments:
            return None
        cache = self.fragments[cid]
        if fid not in cache:
            return None
        return cache[fid]

    def addFragment(self, cid: int, fid: int, frag: bytes):
        """Store a glyph fragment."""
        if cid not in self.fragments:
            self.fragments[cid] = {}

        cache = self.fragments[cid]
        cache[fid] = frag
