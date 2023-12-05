# PyRDP Convert

`pyrdp-convert` is a helper tool to help manipulate network traces and PyRDP session replay files.
It supports conversions of network captures or replay files into various formats.
This document contains format-specific notes.

Use `pyrdp-convert -h` for a full list of supported arguments and formats.


## MP4

MP4s are output with the following specs:

```
H.264 YUV420p @ 30fps
Native (Session Screen) Resolution
```

## JSON

The JSON output format follows the following example schema:

```json
        {
            "info": {
                "date": 1000, // UNIX timestamp
                "host": "HOSTNAME",
                "width": 1920,
                "height: 1080,
                "username": "USERNAME",
                "password": "PASSWORD",
                "domain": "DOMAIN",
            },

            "events": [
                {
                    "timestamp": 10000,
                    "type": "clipboard" | "key" | "mouse" | "unicode",
                    "data":  { ... EventData ... }
                }
            ]
        }
```

Event data is specific to the type of event that is being recorded:

**Clipboard**
```json
        {
            "mime": "text" | "blob",
            "file": "filename" | null,
            "content": "utf8-text" | [0x41, ...]
        }
```

**Key and Unicode**
```json
        {
            "press": true, // Whether it's a key press or release (true|false)
            "key": "a", // Key name
            "mods": ["alt", "ctrl", "shift"] // Modifiers that were held during press
        }
```

**Mouse**
```json
        {
            "x": 100,
            "y": 100,
            "buttons": [
                "left": true, // If present, whether pressed or released.
                "right": false,
                "middle": false,
            ]
        }
```

