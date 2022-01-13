# RDP Protocol

[CyberArk has a great resource](https://www.cyberark.com/resources/threat-research-blog/explain-like-i-m-5-remote-desktop-protocol-rdp) that introduces the RDP protocol.


# The PyRDP library
Our RDP implementation was designed so it could be used for tools other than our MITM.

## Quick Resources

- The PyRDP [Networking Layers Architecture][layers]
- [MS-RDPBCGR][MS-RDPBCGR]: Basic Connectivity and Graphics Remoting
- [MS-RDPEGDI][MS-RDPEGDI]: The Graphics Device Interface Extensions
- [RDP Connection Sequence][connection]


## Overview

This document is specific to PyRDP and assumes a level of familiarity
with the RDP protocol.  RDP is an open specification and all documents
can be found on Microsoft's website.

We recommend a level of familiarity with the [basic protocol][MS-RDPBCGR] 
and more specifically the [connection sequence][connection].


This document is split into several sections. The first section offers
a high level summary of each module that makes up PyRDP, and the
following sections dive into the specifics of each individual modules. 

**NOTE:** This document is a work in progress and should be viewed as
a supplement to diving into the source code, not an alternative. If
you have specific questions about the architecture, feel free to reach
out to the maintainers.


[MS-RDPBCGR]: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/5073f4ed-1e93-45e1-b039-6e30c385867c
[connection]: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/023f1e69-cfe8-4ee6-9ee0-7e759fb4e4ee

### High Level Architecture

PyRDP is split into several modules. This section attempts to give a
high level view of the purpose of each module and how they interact
with one another.

The **core** module contains essential code that is used across the
entire project. These are stand-alone primitives and helper functions
that are highly reusable. Examples include:

- BER Encoding
- Configuration File Management
- Stream Parsing and Packing Helpers
- Twisted Primitives
- Base Types, Abstract Classes and Interfaces


The **enum** module exposes constants that are proper to the RDP
protocol and not internal to a specific module. These include:

- Keyboard scancodes
- RDP message types
- Bitfield flags specific to messages and protocol data units (PDUs)


The **layer** module contains the core of the PyRDP networking
stack. A [separate document][layers] explains the data flow through
layers and is essential to understanding how the data flows between
the client connection and the server connection. Each protocol is
separated into its own layer class. The layer mechanism is also used
to abstract recording to disk.


The **logging** module offers support for uniform logging throughout
the PyRDP project. It provides custom formatters and primitives for
filtering log output.


The **mcs** module provides abstractions for RDP data channels.


The **mitm** module is the main component responsible for connection
interception and tampering. It contains interception facilities for
each layer of the protocol and hooks to inspect and modify data.  It
also contains the application logic for the MITM server and
establishing connectivity with the target server.


The **pdu** module centralizes classes to represent all of the
supported RDP message types. These PDUs can be read and written from a
connection and are the main view into the RDP data stream. Example PDUs
include:

- DemandActive
- ConfirmActive
- ClientInfo


The **parser** module is the heart of the RDP implementation. This is
where the wire protocol is converted from raw bytes into PDUs and from
PDUs back into raw bytes. Parsers are split according to the protocol
layer they operate on and follow the same logical structure as the RDP
specification. Here are some example parsers:

- SlowPathParser
- FastPathParser
- BitmapParser


The **player** module contains code and logic for the Player component
to render an actual RDP session into various forms. The most common
form is to render to the player window, but other types of rendering
are possible (text-only, for example) and can be implemented here.


The **recording** module offers capabilities to export an RDP session
to disk for later replay.


The **security** module deals with everything related to cryptography
in the RDP protocol


The **ui** module contains additional primitives that belong to the
player. The `player` module should be preferred when contributing new
code to PyRDP.


[todo]: More documentation

### General Data Flow for a Typical Connection
### The `mitm` Module In-Depth
### The `parser` Module In-Depth
### Adding Support for a new PDU
### Inspecting Client/Server Capability Sets 

[layers]: layers.md
