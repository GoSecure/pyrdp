from PySide2.QtGui import QPainter

# All raster operations defined by [MS-RDPEGDI] Section 2.2.2.2.1.1.1.7
BLACKNESS = 0x00
DPSoon = 0x01
DPSona = 0x02
PSon = 0x03
SDPona = 0x04
DPon = 0x05
PDSxnon = 0x06
PDSaon = 0x07
SDPnaa = 0x08
PDSxon = 0x09
DPna = 0x0A
PSDnaon = 0x0B
SPna = 0x0C
PDSnaon = 0x0D
PDSonon = 0x0E
Pn = 0x0F
PDSona = 0x10
NOTSRCERASE = 0x11
SDPxnon = 0x12
SDPaon = 0x13
DPSxnon = 0x14
DPSaon = 0x15
PSDPSanaxx = 0x16
SSPxDSxaxn = 0x17
SPxPDxa = 0x18
SDPSanaxn = 0x19
PDSPaox = 0x1A
SDPSxaxn = 0x1B
PSDPaox = 0x1C
DSPDxaxn = 0x1D
PDSox = 0x1E
PDSoan = 0x1F
DPSnaa = 0x20
SDPxon = 0x21
DSna = 0x22
SPDnaon = 0x23
SPxDSxa = 0x24
PDSPanaxn = 0x25
SDPSaox = 0x26
SDPSxnox = 0x27
DPSxa = 0x28
PSDPSaoxxn = 0x29
DPSana = 0x2A
SSPxPDxaxn = 0x2B
SPDSoax = 0x2C
PSDnox = 0x2D
PSDPxox = 0x2E
PSDnoan = 0x2F
PSna = 0x30
SDPnaon = 0x31
SDPSoox = 0x32
NOTSRCCOPY = 0x33
SPDSaox = 0x34
SPDSxnox = 0x35
SDPox = 0x36
SDPoan = 0x37
PSDPoax = 0x38
SPDnox = 0x39
SPDSxox = 0x3A
SPDnoan = 0x3B
PSx = 0x3C
SPDSonox = 0x3D
SPDSnaox = 0x3E
PSan = 0x3F
PSDnaa = 0x40
DPSxon = 0x41
SDxPDxa = 0x42
SPDSanaxn = 0x43
SRCERASE = 0x44
DPSnaon = 0x45
DSPDaox = 0x46
PSDPxaxn = 0x47
SDPxa = 0x48
PDSPDaoxxn = 0x49
DPSDoax = 0x4A
PDSnox = 0x4B
SDPana = 0x4C
SSPxDSxoxn = 0x4D
PDSPxox = 0x4E
PDSnoan = 0x4F
PDna = 0x50
DSPnaon = 0x51
DPSDaox = 0x52
SPDSxaxn = 0x53
DPSonon = 0x54
DSTINVERT = 0x55
DPSox = 0x56
DPSoan = 0x57
PDSPoax = 0x58
DPSnox = 0x59
PATINVERT = 0x5A
DPSDonox = 0x5B
DPSDxox = 0x5C
DPSnoan = 0x5D
DPSDnaox = 0x5E
DPan = 0x5F
PDSxa = 0x60
DSPDSaoxxn = 0x61
DSPDoax = 0x62
SDPnox = 0x63
SDPSoax = 0x64
DSPnox = 0x65
SRCINVERT = 0x66
SDPSonox = 0x67
DSPDSonoxxn = 0x68
PDSxxn = 0x69
DPSax = 0x6A
PSDPSoaxxn = 0x6B
SDPax = 0x6C
PDSPDoaxxn = 0x6D
SDPSnoax = 0x6E
PDSxnan = 0x6F
PDSana = 0x70
SSDxPDxaxn = 0x71
SDPSxox = 0x72
SDPnoan = 0x73
DSPDxox = 0x74
DSPnoan = 0x75
SDPSnaox = 0x76
DSan = 0x77
PDSax = 0x78
DSPDSoaxxn = 0x79
DPSDnoax = 0x7A
SDPxnan = 0x7B
SPDSnoax = 0x7C
DPSxnan = 0x7D
SPxDSxo = 0x7E
DPSaan = 0x7F
DPSaa = 0x80
SPxDSxon = 0x81
DPSxna = 0x82
SPDSnoaxn = 0x83
SDPxna = 0x84
PDSPnoaxn = 0x85
DSPDSoaxx = 0x86
PDSaxn = 0x87
SRCAND = 0x88
SDPSnaoxn = 0x89
DSPnoa = 0x8A
DSPDxoxn = 0x8B
SDPnoa = 0x8C
SDPSxoxn = 0x8D
SSDxPDxax = 0x8E
PDSanan = 0x8F
PDSxna = 0x90
SDPSnoaxn = 0x91
DPSDPoaxx = 0x92
SPDaxn = 0x93
PSDPSoaxx = 0x94
DPSaxn = 0x95
DPSxx = 0x96
PSDPSonoxx = 0x97
SDPSonoxn = 0x98
DSxn = 0x99
DPSnax = 0x9A
SDPSoaxn = 0x9B
SPDnax = 0x9C
DSPDoaxn = 0x9D
DSPDSaoxx = 0x9E
PDSxan = 0x9F
DPa = 0xA0
PDSPnaoxn = 0xA1
DPSnoa = 0xA2
DPSDxoxn = 0xA3
PDSPonoxn = 0xA4
PDxn = 0xA5
DSPnax = 0xA6
PDSPoaxn = 0xA7
DPSoa = 0xA8
DPSoxn = 0xA9
DSTCOPY = 0xAA
DPSono = 0xAB
SPDSxax = 0xAC
DPSDaoxn = 0xAD
DSPnao = 0xAE
DPno = 0xAF
PDSnoa = 0xB0
PDSPxoxn = 0xB1
SSPxDSxox = 0xB2
SDPanan = 0xB3
PSDnax = 0xB4
DPSDoaxn = 0xB5
DPSDPaoxx = 0xB6
SDPxan = 0xB7
PSDPxax = 0xB8
DSPDaoxn = 0xB9
DPSnao = 0xBA
MERGEPAINT = 0xBB
SPDSanax = 0xBC
SDxPDxan = 0xBD
DPSxo = 0xBE
DPSano = 0xBF
MERGECOPY = 0xC0
SPDSnaoxn = 0xC1
SPDSonoxn = 0xC2
PSxn = 0xC3
SPDnoa = 0xC4
SPDSxoxn = 0xC5
SDPnax = 0xC6
PSDPoaxn = 0xC7
SDPoa = 0xC8
SPDoxn = 0xC9
DPSDxax = 0xCA
SPDSaoxn = 0xCB
SRCCOPY = 0xCC
SDPono = 0xCD
SDPnao = 0xCE
SPno = 0xCF
PSDnoa = 0xD0
PSDPxoxn = 0xD1
PDSnax = 0xD2
SPDSoaxn = 0xD3
SSPxPDxax = 0xD4
DPSanan = 0xD5
PSDPSaoxx = 0xD6
DPSxan = 0xD7
PDSPxax = 0xD8
SDPSaoxn = 0xD9
DPSDanax = 0xDA
SPxDSxan = 0xDB
SPDnao = 0xDC
SDno = 0xDD
SDPxo = 0xDE
SDPano = 0xDF
PDSoa = 0xE0
PDSoxn = 0xE1
DSPDxax = 0xE2
PSDPaoxn = 0xE3
SDPSxax = 0xE4
PDSPaoxn = 0xE5
SDPSanax = 0xE6
SPxPDxan = 0xE7
SSPxDSxax = 0xE8
DSPDSanaxxn = 0xE9
DPSao = 0xEA
DPSxno = 0xEB
SDPao = 0xEC
SDPxno = 0xED
SRCPAINT = 0xEE
SDPnoo = 0xEF
PATCOPY = 0xF0
PDSono = 0xF1
PDSnao = 0xF2
PSno = 0xF3
PSDnao = 0xF4
PDno = 0xF5
PDSxo = 0xF6
PDSano = 0xF7
PDSao = 0xF8
PDSxno = 0xF9
DPo = 0xFA
PATPAINT = 0xFB
PSo = 0xFC
PSDnoo = 0xFD
DPSoo = 0xFE
WHITENESS = 0xFF


# Mapping to supported Qt operations.
_rop2 = [
    None,
    QPainter.RasterOp_ClearDestination,  # 0
    QPainter.RasterOp_NotSourceAndNotDestination,  # DPon
    QPainter.RasterOp_NotSourceAndDestination,  # DPna
    QPainter.RasterOp_NotSource,  # Pn
    QPainter.RasterOp_SourceAndNotDestination,  # PDna
    QPainter.RasterOp_NotDestination,  # Dn
    QPainter.RasterOp_SourceXorDestination,  # DPx
    QPainter.RasterOp_NotSourceOrNotDestination,  # DPan
    QPainter.RasterOp_SourceAndDestination,  # DPa
    QPainter.RasterOp_NotSourceXorDestination,  # DPxn
    QPainter.CompositionMode_Destination,  # D
    QPainter.RasterOp_NotSourceOrDestination,  # DPno
    QPainter.CompositionMode_Source,  # P
    QPainter.RasterOp_SourceOrNotDestination,  # PDno
    QPainter.RasterOp_SourceOrDestination,  # PDo
    QPainter.RasterOp_SetDestination,  # 1
]

_rop3 = {
    BLACKNESS: QPainter.RasterOp_ClearDestination,
    DPon: QPainter.RasterOp_NotSourceAndNotDestination,
    DPna: QPainter.RasterOp_NotSourceAndDestination,
    Pn: QPainter.RasterOp_NotSource,
    NOTSRCERASE: QPainter.RasterOp_NotSourceAndNotDestination,
    DSna: QPainter.RasterOp_NotSourceAndDestination,
    NOTSRCCOPY: QPainter.RasterOp_NotSource,
    SRCERASE: QPainter.RasterOp_SourceAndNotDestination,
    PDna: QPainter.RasterOp_SourceAndNotDestination,
    DSTINVERT: QPainter.RasterOp_NotDestination,
    PATINVERT: QPainter.RasterOp_SourceXorDestination,
    DPan: QPainter.RasterOp_NotSourceOrNotDestination,
    SRCINVERT: QPainter.RasterOp_SourceXorDestination,
    DSan: QPainter.RasterOp_NotSourceOrNotDestination,
    SRCAND: QPainter.RasterOp_SourceAndDestination,
    DSxn: QPainter.RasterOp_NotSourceXorDestination,
    DPa: QPainter.RasterOp_SourceAndDestination,
    PDxn: QPainter.RasterOp_NotSourceXorDestination,
    DSTCOPY: QPainter.CompositionMode_Destination,
    DPno: QPainter.RasterOp_NotSourceOrDestination,
    MERGEPAINT: QPainter.RasterOp_NotSourceOrDestination,
    SRCCOPY: QPainter.CompositionMode_Source,
    SDno: QPainter.RasterOp_SourceOrNotDestination,
    SRCPAINT: QPainter.RasterOp_SourceOrDestination,
    PATCOPY: QPainter.CompositionMode_Source,
    PDno: QPainter.RasterOp_SourceOrNotDestination,
    DPo: QPainter.RasterOp_SourceOrDestination,
    WHITENESS: QPainter.RasterOp_SetDestination,
    PSDPxax: QPainter.RasterOp_SourceAndDestination,
}


def set_rop3(op: int, painter: QPainter):
    """
    Configure a QPainter with the required ternary raster operation.

    :parma op: The operation identifier.
    :param painter: The painter being used.
    :returns: The operation that will be processed.
    """
    if op not in _rop3:
        return None

    mode = _rop3[op]
    painter.setCompositionMode(mode)
    return mode


def set_rop2(op: int, painter: QPainter):
    """
    Configure a QPainter with the required binary raster operation.

    :parma op: The operation identifier.
    :param painter: The painter being used.
    :returns: The operation that will be processed.
    """
    if op < 0 or op >= len(_rop2):
        return None
    mode = _rop2[op]
    painter.setCompositionMode(mode)
    return mode


def rop_slow(code: str, dst, src, pal):
    """
    Slow but generic fallback implementation of raster operations.

    This function implements the RPN-notation described in [MS-RDPEGDI][1]
    with a generic stack machine. It is much slower than having a hardcoded
    and optimized function for a particular operation, but greatly reduces
    the amount of code required.

    [1]: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/a9a85075-e796-45eb-b84a-f399324a1109
    """

    stack = []
    for c in code:
        if c == 'D':
            stack.append(dst)
        elif c == 'S':
            stack.append(src)
        elif c == 'P':
            if pal is None:
                raise SyntaxError('Palette is not present.')
            stack.append(pal)
        else:
            lhs = stack.pop()
            rhs = None
            res = lhs  # TODO: Actually perform the operation.

            if c != 'n':
                rhs = stack.pop()

            if c == 'x':  # XOR
                print(f'{lhs} ^ {rhs}')
            elif c == 'n':  # NOT
                print(f'~{lhs}')
            elif c == 'a':  # AND
                print(f'{lhs} & {rhs}')
            elif c == 'o':  # OR
                print(f'{lhs} | {rhs}')

            stack.append(res)
    out = stack.pop()

    assert len(stack) == 0
    return out
