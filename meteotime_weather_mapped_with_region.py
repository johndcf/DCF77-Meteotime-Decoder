#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ------------------------------------------------------------
# Meteotime Decoder (DCF77)
# ------------------------------------------------------------
# This implementation decodes Meteotime weather data from DCF77.
#
# IMPORTANT IMPLEMENTATION NOTE:
# The decoded payload bits are NOT directly aligned with the
# official Meteotime PDF bit order.
#
# After decryption and byte assembly, the bit order within fields
# appears to be reversed (LSB/MSB mismatch).
#
# Therefore:
# - Weather codes (day/night) are bit-reversed (swab_nibble)
# - Bits 8..11 are bit-reversed as one 4-bit field
#   * if Bit 15 == 0: interpreted as extreme weather code
#   * if Bit 15 == 1: interpreted as relative morning weather (bits 8..9)
#                     and sunshine duration (bits 10..11)
# - Rain probability field is bit-reversed
# - Temperature (6-bit) is reconstructed bit-by-bit (LSB-first)
#
# This behavior was verified empirically:
# - Summer (05 Aug): only reversed interpretation is plausible
# - Winter (24 Dec): reversed interpretation also matches
#
# Conclusion:
# The "mirrored" seems to be REQUIRED for correct results.
# But there is no final prove for that interpretation of the payload,
# it is best current payload interpretation.
#
# Decrypt / payload build: correct  
# Day/Night: very likely correct  
# Temperature: very likely correct  
# Extreme/Wind: likely correct  
# Rain: probably correct, but the weakest part from a formal standpoint
# ------------------------------------------------------------

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import re
from dataclasses import dataclass
from datetime import date
from typing import List, Optional

LINE_RE = re.compile(
    r'^\s*([01])\s+([01]{14})\s+([01]{6})\s+([01]{8})\s+([01]{7})\s+([01]{6})\s+([01]{3})\s+([01]{5})\s+([01]{9}).*?(\d{2})\.(\d{2})\.(\d{2})\s+(\d{2}):(\d{2}):(\d{2})'
)

mUintArrBitPattern12 = [0x80000,0x00010,0x00008,0x00100,0x00080,0x01000,0x00800,0x10000,0x08000,0x00001,0x00000,0x00000]
mUintArrBitPattern30_1 = [
0x00000200,0x00000020,0x02000000,0x00000000,0x00000000,0x00000080,0x40000000,0x01000000,
0x04000000,0x00000000,0x00010000,0x00000000,0x00400000,0x00000010,0x00200000,0x00080000,
0x00004000,0x00000000,0x00020000,0x00100000,0x00008000,0x00000040,0x00001000,0x00000400,
0x00000001,0x80000000,0x00000008,0x00000002,0x00040000,0x10000000]
mUintArrBitPattern30_2 = [
0x00,0x00,0x00,0x08,0x20,0x00,0x00,0x00,
0x00,0x10,0x00,0x04,0x00,0x00,0x00,0x00,
0x00,0x40,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00]
mUintArrBitPattern20 = [
0x000004,0x002000,0x008000,0x400000,0x000100,0x100000,0x000400,0x800000,
0x040000,0x020000,0x000008,0x000200,0x004000,0x000002,0x001000,0x080000,
0x000800,0x200000,0x010000,0x000001]
mByteArrLookupTable1C_1 = [
0xBB,0x0E,0x22,0xC5,0x73,0xDF,0xF7,0x6D,0x90,0xE9,0xA1,0x38,0x1C,0x84,0x4A,0x56,
0x64,0x8D,0x28,0x0B,0xD1,0xBA,0x93,0x52,0x1C,0xC5,0xA7,0xF0,0xE9,0x7F,0x36,0x4E,
0xC1,0x77,0x3D,0xB3,0xAA,0xE0,0x0C,0x6F,0x14,0x88,0xF6,0x2B,0xD2,0x99,0x5E,0x45,
0x1F,0x70,0x96,0xD3,0xB3,0x0B,0xFC,0xEE,0x81,0x42,0xCA,0x34,0xA5,0x58,0x29,0x67]
mByteArrLookupTable1C_2 = [
0xAB,0x3D,0xFC,0x74,0x65,0xE6,0x0E,0x4F,0x97,0x11,0xD8,0x59,0x83,0xC2,0xBA,0x20,
0xC5,0x1B,0xD2,0x58,0x49,0x37,0x01,0x7D,0x93,0xFA,0xE0,0x2F,0x66,0xB4,0xAC,0x8E,
0xB7,0xCC,0x43,0xFF,0x58,0x66,0xEB,0x35,0x82,0x2A,0x99,0xDD,0x00,0x71,0x14,0xAE,
0x4E,0xB1,0xF7,0x70,0x18,0x52,0xAA,0x9F,0xD5,0x6B,0xCC,0x3D,0x04,0x83,0xE9,0x26]
mByteArrLookupTable1C_3 = [
0x0A,0x02,0x00,0x0F,0x06,0x07,0x0D,0x08,0x03,0x0C,0x0B,0x05,0x09,0x01,0x04,0x0E,
0x02,0x09,0x05,0x0D,0x0C,0x0E,0x0F,0x08,0x06,0x07,0x0B,0x01,0x00,0x0A,0x04,0x03,
0x08,0x00,0x0D,0x0F,0x01,0x0C,0x03,0x06,0x0B,0x04,0x09,0x05,0x0A,0x07,0x02,0x0E,
0x03,0x0D,0x00,0x0C,0x09,0x06,0x0F,0x0B,0x01,0x0E,0x08,0x0A,0x02,0x07,0x04,0x05]

WEATHER_CODES_DAY = {
    0: "--", 1: "Sonnig", 2: "Leicht bewölkt", 3: "Vorwiegend bewölkt",
    4: "Bedeckt", 5: "Hochnebel", 6: "Nebel", 7: "Regenschauer",
    8: "Leichter Regen", 9: "Starker Regen", 10: "Frontengewitter",
    11: "Wärmegewitter", 12: "Schneeregenschauer", 13: "Schneeschauer",
    14: "Schneeregen", 15: "Schneefall",
}

WEATHER_CODES_NIGHT = {
    0: "--", 1: "Klar", 2: "Leicht bewölkt", 3: "Vorwiegend bewölkt",
    4: "Bedeckt", 5: "Hochnebel", 6: "Nebel", 7: "Regenschauer",
    8: "Leichter Regen", 9: "Starker Regen", 10: "Frontengewitter",
    11: "Wärmegewitter", 12: "Schneeregenschauer", 13: "Schneeschauer",
    14: "Schneeregen", 15: "Schneefall",
}

EXTREME_CODES = {
    0: "Kein", 1: "Schweres Wetter 24 Std.", 2: "Schweres Wetter Tag",
    3: "Schweres Wetter Nacht", 4: "Sturm", 5: "Sturm Tag",
    6: "Sturm Nacht", 7: "Böen Tag", 8: "Böen Nacht",
    9: "Eisregen Vormittag", 10: "Eisregen Nachmittag",
    11: "Eisregen Nacht", 12: "Feinstaub", 13: "Ozon",
    14: "Radiation", 15: "Hochwasser",
}

ANOMALY_JUMP_CODES = {
    0: "gleiches Wetter",
    1: "Sprung 1",
    2: "Sprung 2",
    3: "Sprung 3",
}

SUNSHINE_DURATION_CODES = {
    0: "0 - 2 Std.",
    1: "2 - 4 Std.",
    2: "5 - 6 Std.",
    3: "7 - 8 Std.",
}
WIND_DIRECTION_CODES = {
    0: "reserviert",
    1: "reserviert",
    2: "reserviert",
    3: "reserviert",
    4: "reserviert",
    5: "reserviert",
    6: "reserviert",
    7: "reserviert",
    8: "reserviert",
    9: "reserviert",
    10: "reserviert",
    11: "reserviert",
    12: "reserviert",
    13: "reserviert",
    14: "reserviert",
    15: "reserviert",
    16: "N",
    17: "NO",
    18: "O",
    19: "SO",
    20: "S",
    21: "SW",
    22: "W",
    23: "NW",
    24: "wechselnd",
    25: "Fön",
    26: "Biese NO",
    27: "Mistral N",
    28: "Scirocco S",
    29: "Tramont. W",
    30: "reserviert",
    31: "reserviert",
    32: "N",
    33: "NO",
    34: "O",
    35: "SO",
    36: "S",
    37: "SW",
    38: "W",
    39: "NW",
    40: "wechselnd",
    41: "Fön",
    42: "Biese NO",
    43: "Mistral N",
    44: "Scirocco S",
    45: "Tramont. W",
    46: "reserviert",
    47: "reserviert",
    48: "N",
    49: "NO",
    50: "O",
    51: "SO",
    52: "S",
    53: "SW",
    54: "W",
    55: "NW",
    56: "wechselnd",
    57: "Fön",
    58: "Biese NO",
    59: "Mistral N",
    60: "Scirocco S",
    61: "Tramont. W",
    62: "reserviert",
    63: "reserviert",
    64: "N",
    65: "NO",
    66: "O",
    67: "SO",
    68: "S",
    69: "SW",
    70: "W",
    71: "NW",
    72: "wechselnd",
    73: "Fön",
    74: "Biese NO",
    75: "Mistral N",
    76: "Scirocco S",
    77: "Tramont. W",
    78: "reserviert",
    79: "reserviert",
    80: "N",
    81: "NO",
    82: "O",
    83: "SO",
    84: "S",
    85: "SW",
    86: "W",
    87: "NW",
    88: "wechselnd",
    89: "Fön",
    90: "Biese NO",
    91: "Mistral N",
    92: "Scirocco S",
    93: "Tramont. W",
    94: "reserviert",
    95: "reserviert",
    96: "N",
    97: "NO",
    98: "O",
    99: "SO",
    100: "S",
    101: "SW",
    102: "W",
    103: "NW",
    104: "wechselnd",
    105: "Fön",
    106: "Biese NO",
    107: "Mistral N",
    108: "Scirocco S",
    109: "Tramont. W",
    110: "reserviert",
    111: "reserviert",
    112: "N",
    113: "NO",
    114: "O",
    115: "SO",
    116: "S",
    117: "SW",
    118: "W",
    119: "NW",
    120: "wechselnd",
    121: "Fön",
    122: "Biese NO",
    123: "Mistral N",
    124: "Scirocco S",
    125: "Tramont. W",
    126: "reserviert",
    127: "reserviert",
}

WIND_FORCE = {
    0: "0",
    1: "0-2",
    2: "3-4",
    3: "5-6",
    4: "7",
    5: "8",
    6: "9",
    7: ">=10",
}

REGIONS_ALL = {
    0: "Bordeaux", 1: "La Rochelle", 2: "Paris", 3: "Brest", 4: "Clermont-Ferrand",
    5: "Béziers", 6: "Bruxelles", 7: "Dijon", 8: "Marseille", 9: "Lyon",
    10: "Grenoble", 11: "La Chaux-de-Fonds", 12: "Frankfurt am Main", 13: "Westl. Mittelgebirge",
    14: "Duisburg", 15: "Swansea", 16: "Manchester", 17: "Le Havre", 18: "London",
    19: "Bremerhaven", 20: "Herning", 21: "Århus", 22: "Hannover", 23: "København",
    24: "Rostock", 25: "Ingolstadt", 26: "München", 27: "Bolzano", 28: "Nürnberg",
    29: "Leipzig", 30: "Erfurt", 31: "Lausanne", 32: "Zürich", 33: "Adelboden",
    34: "Sion", 35: "Glarus", 36: "Davos", 37: "Kassel", 38: "Locarno",
    39: "Sestriere", 40: "Milano", 41: "Roma", 42: "Amsterdam", 43: "Génova",
    44: "Venezia", 45: "Strasbourg", 46: "Klagenfurt", 47: "Innsbruck", 48: "Salzburg",
    49: "Bratislava", 50: "Praha", 51: "Decin", 52: "Berlin", 53: "Göteborg",
    59: "Stuttgart",
    60: "Napoli", 61: "Ancona", 62: "Bari", 63: "Budapest", 64: "Madrid",
    65: "Bilbao", 66: "Palermo", 67: "Palma de Mallorca", 68: "Valencia", 69: "Barcelona",
    70: "Andorra", 71: "Sevilla", 72: "Lissabon", 73: "Sassari", 74: "Gijon",
    75: "Galway", 76: "Dublin", 77: "Glasgow", 78: "Stavanger", 79: "Trondheim",
    80: "Sundsvall", 81: "Gdansk", 82: "Warszawa", 83: "Krakow", 84: "Umea",
    85: "Oestersund", 86: "Samedan", 87: "Zagreb", 88: "Zermatt", 89: "Split",
}

SECTION_INFO = {
    0: ("Heute", "Hoch", "Extrem/Regen"),
    1: ("Heute", "Tief", "Wind"),
    2: ("Tag 1", "Hoch", "Extrem/Regen"),
    3: ("Tag 1", "Tief", "Wind"),
    4: ("Tag 2", "Hoch", "Extrem/Regen"),
    5: ("Tag 2", "Tief", "Wind"),
    6: ("Tag 3", "Hoch", "Extrem/Regen"),
    7: ("Tag 3", "Wind/Anomalie", "Wind"),
}


def get_region_meta(region_id: int):
    name = REGIONS_ALL.get(region_id, f'Region {region_id}')
    forecast_days = 4 if region_id <= 59 else 2
    return name, forecast_days

@dataclass
class Row:
    weather: str
    info: str
    minutebits: str
    hourbits: str
    daybits: str
    wotbits: str
    monthbits: str
    yearbits: str
    dd: int
    mo: int
    yy: int
    hh: int
    mm: int
    ss: int

class ByteUInt:
    def __init__(self): self.FullUint = 0
    @property
    def Byte0(self): return self.FullUint & 0xFF
    @Byte0.setter
    def Byte0(self, v): self.FullUint = (self.FullUint & ~0xFF) | (v & 0xFF)
    @property
    def Byte1(self): return (self.FullUint >> 8) & 0xFF
    @Byte1.setter
    def Byte1(self, v): self.FullUint = (self.FullUint & ~(0xFF << 8)) | ((v & 0xFF) << 8)
    @property
    def Byte2(self): return (self.FullUint >> 16) & 0xFF
    @Byte2.setter
    def Byte2(self, v): self.FullUint = (self.FullUint & ~(0xFF << 16)) | ((v & 0xFF) << 16)
    @property
    def Byte3(self): return (self.FullUint >> 24) & 0xFF
    @Byte3.setter
    def Byte3(self, v): self.FullUint = (self.FullUint & ~(0xFF << 24)) | ((v & 0xFF) << 24)

class Container:
    def __init__(self):
        self.mByteUint1 = ByteUInt()
        self.mByteUint2 = ByteUInt()
        self.mByteUint3 = ByteUInt()
        self.mByteUint4 = ByteUInt()
        self.mByteUpperTime2 = 0
        self.mUintLowerTime = 0


def parse_rows(path: str) -> List[Row]:
    out = []
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            m = LINE_RE.match(line)
            if not m:
                continue
            _, weather, info, minutebits, hourbits, daybits, wotbits, monthbits, yearbits, dd, mo, yy, hh, mm, ss = m.groups()
            out.append(Row(weather, info, minutebits, hourbits, daybits, wotbits, monthbits, yearbits,
                           int(dd), int(mo), int(yy), int(hh), int(mm), int(ss)))
    return out


def parity_ok(a, s, e):
    return (sum(a[s:e]) & 1) == a[e]


def parse_message(r: Row):
    a = [0] * 60
    for i, ch in enumerate(r.weather, start=1): a[i] = 1 if ch == '1' else 0
    for i, ch in enumerate(r.info, start=15): a[i] = 1 if ch == '1' else 0
    for i, ch in enumerate(r.minutebits, start=21): a[i] = 1 if ch == '1' else 0
    for i, ch in enumerate(r.hourbits, start=29): a[i] = 1 if ch == '1' else 0
    for i, ch in enumerate(r.daybits, start=36): a[i] = 1 if ch == '1' else 0
    for i, ch in enumerate(r.wotbits, start=42): a[i] = 1 if ch == '1' else 0
    for i, ch in enumerate(r.monthbits, start=45): a[i] = 1 if ch == '1' else 0
    for i, ch in enumerate(r.yearbits, start=50): a[i] = 1 if ch == '1' else 0
    return a


def CopyTimeToByteUint(data, key, c: Container):
    c.mByteUint1.FullUint = c.mByteUint2.FullUint = c.mByteUint3.FullUint = 0
    c.mUintLowerTime = 0
    c.mByteUpperTime2 = 0
    for i in range(4):
        c.mUintLowerTime = ((c.mUintLowerTime << 8) | key[3 - i]) & 0xFFFFFFFF
    c.mByteUpperTime2 = key[4]
    c.mByteUint3.Byte0 = data[2]
    c.mByteUint3.Byte1 = data[3]
    c.mByteUint3.Byte2 = data[4]
    c.mByteUint3.FullUint >>= 4
    c.mByteUint2.Byte0 = data[0]
    c.mByteUint2.Byte1 = data[1]
    c.mByteUint2.Byte2 = data[2] & 0x0F


def ShiftTimeRight(round_, c: Container):
    count = 2 if round_ in (16, 8, 7, 3) else 1
    while count:
        count -= 1
        tmp = 1 if (c.mUintLowerTime & 0x00100000) else 0
        c.mUintLowerTime &= 0xFFEFFFFF
        if c.mUintLowerTime & 1:
            c.mUintLowerTime |= 0x00100000
        c.mUintLowerTime >>= 1
        if c.mByteUpperTime2 & 1:
            c.mUintLowerTime |= 0x80000000
        c.mByteUpperTime2 >>= 1
        if tmp:
            c.mByteUpperTime2 |= 0x80
        c.mUintLowerTime &= 0xFFFFFFFF
        c.mByteUpperTime2 &= 0xFF


def ExpandR(c: Container):
    c.mByteUint3.FullUint &= 0x000FFFFF
    tmp = 0x00100000
    for i in range(12):
        if c.mByteUint3.FullUint & mUintArrBitPattern12[i]:
            c.mByteUint3.FullUint |= tmp
        tmp <<= 1
    c.mByteUint3.FullUint &= 0xFFFFFFFF


def CompressKey(c: Container):
    tmp = 1
    c.mByteUint1.FullUint = 0
    for i in range(30):
        if (c.mUintLowerTime & mUintArrBitPattern30_1[i]) or (c.mByteUpperTime2 & mUintArrBitPattern30_2[i]):
            c.mByteUint1.FullUint |= tmp
        tmp <<= 1
    c.mByteUint1.FullUint &= 0xFFFFFFFF


def DoSbox(c: Container):
    helper = c.mByteUint1.Byte3
    c.mByteUint1.Byte3 = c.mByteUint1.Byte2
    c.mByteUint4.FullUint = 0
    for i in range(5, 0, -1):
        if (i & 1) == 0:
            tmp = (c.mByteUint1.Byte0 >> 4) | ((c.mByteUint1.Byte0 & 0x0F) << 4)
            c.mByteUint1.Byte0 = tmp
        c.mByteUint1.Byte3 &= 0xF0
        tmp = ((c.mByteUint1.Byte0 & 0x0F) | c.mByteUint1.Byte3) & 0xFF
        if i & 4:
            tmp = mByteArrLookupTable1C_1[tmp & 0x3F]
        if i & 2:
            tmp = mByteArrLookupTable1C_2[tmp & 0x3F]
        elif i == 1:
            tmp = mByteArrLookupTable1C_3[tmp & 0x3F]
        if i & 1:
            c.mByteUint4.Byte0 = tmp & 0x0F
        else:
            c.mByteUint4.Byte0 |= tmp & 0xF0
        if (i & 1) == 0:
            tmp2 = c.mByteUint1.Byte3
            c.mByteUint1.FullUint >>= 8
            c.mByteUint1.Byte3 = tmp2
            c.mByteUint4.FullUint = (c.mByteUint4.FullUint << 8) & 0xFFFFFFFF
        c.mByteUint1.Byte3 >>= 1
        if helper & 1:
            c.mByteUint1.Byte3 |= 0x80
        helper >>= 1
        c.mByteUint1.Byte3 >>= 1
        if helper & 1:
            c.mByteUint1.Byte3 |= 0x80
        helper >>= 1


def DoPbox(c: Container):
    tmp = 1
    c.mByteUint1.FullUint = 0xFF000000
    for i in range(20):
        if c.mByteUint4.FullUint & mUintArrBitPattern20[i]:
            c.mByteUint1.FullUint |= tmp
        tmp <<= 1
    c.mByteUint1.FullUint &= 0xFFFFFFFF


def decrypt(cipher, key):
    c = Container()
    CopyTimeToByteUint(cipher, key, c)
    for i in range(16, 0, -1):
        ShiftTimeRight(i, c)
        ExpandR(c)
        CompressKey(c)
        c.mByteUint1.FullUint ^= c.mByteUint3.FullUint
        c.mByteUint3.Byte2 &= 0x0F
        DoSbox(c)
        DoPbox(c)
        c.mByteUint1.FullUint ^= c.mByteUint2.FullUint
        c.mByteUint2.FullUint = c.mByteUint3.FullUint & 0x00FFFFFF
        c.mByteUint3.FullUint = c.mByteUint1.FullUint & 0x00FFFFFF
    c.mByteUint3.FullUint = (c.mByteUint3.FullUint << 4) & 0xFFFFFFFF
    c.mByteUint2.Byte2 &= 0x0F
    c.mByteUint2.Byte2 |= c.mByteUint3.Byte0 & 0xF0
    return [c.mByteUint2.Byte0, c.mByteUint2.Byte1, c.mByteUint2.Byte2, c.mByteUint3.Byte1, c.mByteUint3.Byte2]


def flip_byte(x: int) -> int:
    result = 0
    source = x
    for _ in range(8):
        result >>= 1
        result |= source & 0x80
        source = (source << 1) & 0xFF
    return result


def swab_nibble(value: int) -> int:
    out = 0
    for _ in range(4):
        out = (out << 1) | (value & 0x01)
        value >>= 1
    return out


def payload_to_info_bytes(payload: int):
    return list(payload.to_bytes(3, 'big'))


def decode_weather_info(payload: int):
    info = payload_to_info_bytes(payload)
    day_code = swab_nibble(info[0] >> 4)
    night_code = swab_nibble(info[0] & 0x0F)
    anomaly = info[1] & 0x01

    # Bits 8..11 are one mirrored 4-bit field.
    # If anomaly_bit == 0: extreme weather code
    # If anomaly_bit == 1: bits 8..9 = relative morning weather, bits 10..11 = sunshine duration
    bits8_11 = swab_nibble(info[1] >> 4)
    extreme_code = bits8_11
    morning_jump_code = bits8_11 & 0x03
    sunshine_code = (bits8_11 >> 2) & 0x03

    # Rain probability is a 3-bit field in bits 1..3 of info[1].
    # Extract the field cleanly first, then reverse the 3-bit order.
    rain_raw = (info[1] >> 1) & 0x07
    rain_group = ((rain_raw & 0x01) << 2) | (rain_raw & 0x02) | ((rain_raw & 0x04) >> 2)
    rain_percent = min(rain_group * 15, 100)

    temp_raw = info[2] >> 2
    temp_code = 0
    for _ in range(6):
        temp_code = (temp_code << 1) | (temp_raw & 0x01)
        temp_raw >>= 1

    if temp_code == 0:
        temp_text = '< -21 °C'
    elif temp_code == 63:
        temp_text = '> 40 °C'
    else:
        temp_text = f'{temp_code - 22} °C'

    if anomaly == 0:
        bits8_11_mode = 'extreme_weather'
        bits8_11_text = EXTREME_CODES.get(extreme_code, f'Code {extreme_code}')
    else:
        bits8_11_mode = 'weather_anomaly'
        bits8_11_text = (
            f"Relatives Vormittagswetter = {ANOMALY_JUMP_CODES.get(morning_jump_code, f'Code {morning_jump_code}')}, "
            f"Sonnenscheindauer = {SUNSHINE_DURATION_CODES.get(sunshine_code, f'Code {sunshine_code}')}"
        )

    return {
        'payload_hex': f'0x{payload:06X}',
        'info0_hex': f'{info[0]:02X}',
        'info1_hex': f'{info[1]:02X}',
        'info2_hex': f'{info[2]:02X}',
        'day_code': day_code,
        'day_weather': WEATHER_CODES_DAY.get(day_code, f'Code {day_code}'),
        'night_code': night_code,
        'night_weather': WEATHER_CODES_NIGHT.get(night_code, f'Code {night_code}'),
        'anomaly_bit': anomaly,
        'bits8_11_mode': bits8_11_mode,
        'bits8_11_raw_code': bits8_11,
        'bits8_11_text': bits8_11_text,
        'extreme_code': extreme_code,
        'extreme_text': EXTREME_CODES.get(extreme_code, f'Code {extreme_code}'),
        'morning_jump_code': morning_jump_code,
        'morning_jump_text': ANOMALY_JUMP_CODES.get(morning_jump_code, f'Code {morning_jump_code}'),
        'sunshine_code': sunshine_code,
        'sunshine_text': SUNSHINE_DURATION_CODES.get(sunshine_code, f'Code {sunshine_code}'),
        'rain_group': rain_group,
        'rain_percent': rain_percent,
        'wind_dir_code': extreme_code,
        'wind_force_code': rain_group,
        'wind_full_code': (rain_group << 4) | extreme_code,
        'wind_direction': WIND_DIRECTION_CODES.get((rain_group << 4) | extreme_code, f'Code {(rain_group << 4) | extreme_code}'),
        'wind_force': WIND_FORCE.get(rain_group, f'Code {rain_group}'),
        'temp_code': temp_code,
        'temp_text': temp_text,
    }


def last_sunday(year: int, month: int) -> int:
    d = date(year, month + 1, 1) if month < 12 else date(year + 1, 1, 1)
    d = d.fromordinal(d.toordinal() - 1)
    while d.weekday() != 6:
        d = d.fromordinal(d.toordinal() - 1)
    return d.day


def is_dst_europe_local(row: Row) -> bool:
    year = 2000 + row.yy
    if row.mo < 3 or row.mo > 10:
        return False
    if 3 < row.mo < 10:
        return True
    if row.mo == 3:
        ls = last_sunday(year, 3)
        if row.dd > ls:
            return True
        if row.dd < ls:
            return False
        return row.hh >= 2
    ls = last_sunday(year, 10)
    if row.dd < ls:
        return True
    if row.dd > ls:
        return False
    return row.hh < 3


def get_minutes_since_2200_utc_anchor(row: Row) -> int:
    hours = row.hh
    hours -= 1  # CET -> UTC
    if is_dst_europe_local(row):
        hours -= 1
    hours -= 22
    if hours < 0:
        hours += 24
    return row.mm + hours * 60


def get_area_section(row: Row):
    minutes = get_minutes_since_2200_utc_anchor(row)
   # The current time-slot model still decodes the original 60 fixed 3-minute slots.
   # The additional regions 60..89 from the PDF are defined in the region table,
   # but require a separate transmitter/slot mapping for automatic assignment.
    area = (minutes % (60 * 3)) // 3
    area -= 1
    if area < 0:
        area += 60
    section = minutes // (60 * 3)
    return area, section


def add_region_section(mapped: dict, row: Row):
    area, section = get_area_section(row)
    day_label, section_kind, interpretation = SECTION_INFO.get(section, (f'Sektion {section}', '?', '?'))
    region_name, forecast_days = get_region_meta(area)
    mapped['region_id'] = area
    mapped['region_name'] = region_name
    mapped['forecast_days'] = forecast_days
    mapped['section_id'] = section
    mapped['day_label'] = day_label
    mapped['section_kind'] = section_kind
    mapped['interpretation'] = interpretation
    mapped['is_high_section'] = section in (0, 2, 4, 6)
    mapped['is_low_wind_section'] = section in (1, 3, 5, 7)

    if mapped['is_high_section']:
        if mapped['anomaly_bit'] == 0:
            mapped['section_value_text'] = (
                f"Extrem = {mapped['extreme_text']} (Code {mapped['extreme_code']}), "
                f"Regen = {mapped['rain_percent']} %"
            )
        else:
            mapped['section_value_text'] = (
                f"Relatives Vormittagswetter = {mapped['morning_jump_text']} (Code {mapped['morning_jump_code']}), "
                f"Sonnenscheindauer = {mapped['sunshine_text']} (Code {mapped['sunshine_code']}), "
                f"Regen = {mapped['rain_percent']} %"
            )
    else:
        mapped['section_value_text'] = (
            f"Wind = {mapped['wind_direction']} (Code {mapped['wind_dir_code']}), "
            f"Stärke = {mapped['wind_force']} (Code {mapped['wind_force_code']})"
        )
    return mapped


def decode_log(rows: List[Row], limit: Optional[int] = None):
    weather = [0] * 82
    decoded = []
    for r in rows:
        a = parse_message(r)
        if not (a[20] == 1 and parity_ok(a, 21, 28) and parity_ok(a, 29, 35) and parity_ok(a, 36, 58)):
            continue
        minute = (a[21] + a[22]*2 + a[23]*4 + a[24]*8) + 10*(a[25] + a[26]*2 + a[27]*4)
        minute = (minute - 1) & 0xFF
        part = minute % 3
        if part == 0:
            weather = [0] * 82
            for i in range(14): weather[i] = a[i + 1]
        elif part == 1:
            for i in range(14): weather[14 + i] = a[i + 1]
            j = 42
            for i in range(21, 28): weather[j] = a[i]; j += 1
            j += 1
            for i in range(29, 35): weather[j] = a[i]; j += 1
            j += 2
            for i in range(36, 42): weather[j] = a[i]; j += 1
            j += 2
            for i in range(45, 50): weather[j] = a[i]; j += 1
            for i in range(42, 45): weather[j] = a[i]; j += 1
            for i in range(50, 58): weather[j] = a[i]; j += 1
        else:
            for i in range(14): weather[28 + i] = a[i + 1]
            uiBitCnt = 0
            ucTemp = 0
            uiCnt = 1
            cipher = [0] * 5
            key = [0] * 5
            while uiCnt < 42:
                if uiCnt != 7:
                    ucTemp >>= 1
                    if weather[uiCnt] == 1:
                        ucTemp |= 0x80
                    uiBitCnt += 1
                    if (uiBitCnt & 7) == 0:
                        cipher[(uiBitCnt >> 3) - 1] = ucTemp
                uiCnt += 1
            uiBitCnt = 0
            while uiCnt < 82:
                ucTemp >>= 1
                if weather[uiCnt] == 1:
                    ucTemp |= 0x80
                uiBitCnt += 1
                if (uiBitCnt & 7) == 0:
                    key[(uiBitCnt >> 3) - 1] = ucTemp
                uiCnt += 1
            plain = decrypt(cipher, key)
            check = (((plain[2] & 0x0F) << 8) | plain[1]) << 4 | (plain[0] >> 4)
            if check == 0x2501:
                w0 = flip_byte(((plain[3] & 0x0F) << 4) | ((plain[2] & 0xF0) >> 4))
                w1 = flip_byte(((plain[4] & 0x0F) << 4) | ((plain[3] & 0xF0) >> 4))
                w2 = flip_byte(((plain[0] & 0x0F) << 4) | ((plain[4] & 0xF0) >> 4))
                w2 = (w2 & 0xFC) | 0x02
                payload = (w0 << 16) | (w1 << 8) | w2
                mapped = decode_weather_info(payload)
                mapped = add_region_section(mapped, r)
                decoded.append((r, payload, cipher, key, plain, mapped))
                if limit is not None and len(decoded) >= limit:
                    break
    return decoded


def print_decoded(decoded, show_internal=False):
    for r, payload, cipher, key, plain, mapped in decoded:
        ts = f'{r.dd:02d}.{r.mo:02d}.{r.yy:02d} {r.hh:02d}:{r.mm:02d}:{r.ss:02d}'
        print(f'{ts} -> {mapped["payload_hex"]}')
        print(f'  Region:   {mapped["region_id"]} - {mapped["region_name"]} ({mapped["forecast_days"]}-Tagesprognose)')
        print(f'  Sektion:  {mapped["section_id"]} - {mapped["day_label"]} / {mapped["section_kind"]}')
        print(f'  Tag:      {mapped["day_weather"]} (Code {mapped["day_code"]})')
        print(f'  Nacht:    {mapped["night_weather"]} (Code {mapped["night_code"]})')
        print(f'  Temp:     {mapped["temp_text"]} (Code {mapped["temp_code"]})')
        print(f'  Anom.:    {mapped["anomaly_bit"]}')
        print(f'  Wind:     {mapped["wind_direction"]}, Stärke {mapped["wind_force"]} (Code {mapped["wind_full_code"]}, dir={mapped["wind_dir_code"]}, force={mapped["wind_force_code"]})')
        print(f'  Deutung:  {mapped["section_value_text"]}')
        if show_internal:
            print('  cipher:   ' + ' '.join(f'{x:02X}' for x in cipher))
            print('  key:      ' + ' '.join(f'{x:02X}' for x in key))
            print('  plain:    ' + ' '.join(f'{x:02X}' for x in plain))
            print(f'  info:     {mapped["info0_hex"]} {mapped["info1_hex"]} {mapped["info2_hex"]}')


def write_csv(path: str, decoded):
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f, delimiter=';')
        w.writerow([
            'date', 'time', 'region_id', 'region_name', 'forecast_days', 'section_id', 'day_label', 'section_kind',
            'payload_hex', 'info0', 'info1', 'info2',
            'day_code', 'day_weather', 'night_code', 'night_weather',
            'anomaly_bit', 'bits8_11_mode', 'bits8_11_raw_code',
            'extreme_code', 'extreme_text',
            'morning_jump_code', 'morning_jump_text',
            'sunshine_code', 'sunshine_text',
            'rain_group', 'rain_percent',
            'wind_full_code', 'wind_dir_code', 'wind_direction', 'wind_force_code', 'wind_force',
            'temp_code', 'temp_text', 'plain'
        ])
        for r, payload, cipher, key, plain, mapped in decoded:
            w.writerow([
                f'{r.dd:02d}.{r.mo:02d}.{r.yy:02d}', f'{r.hh:02d}:{r.mm:02d}:{r.ss:02d}',
                mapped['region_id'], mapped['region_name'], mapped['forecast_days'], mapped['section_id'], mapped['day_label'], mapped['section_kind'],
                mapped['payload_hex'], mapped['info0_hex'], mapped['info1_hex'], mapped['info2_hex'],
                mapped['day_code'], mapped['day_weather'], mapped['night_code'], mapped['night_weather'],
                mapped['anomaly_bit'], mapped['bits8_11_mode'], mapped['bits8_11_raw_code'],
                mapped['extreme_code'], mapped['extreme_text'],
                mapped['morning_jump_code'], mapped['morning_jump_text'],
                mapped['sunshine_code'], mapped['sunshine_text'],
                mapped['rain_group'], mapped['rain_percent'],
                mapped['wind_full_code'], mapped['wind_dir_code'], mapped['wind_direction'], mapped['wind_force_code'], mapped['wind_force'],
                mapped['temp_code'], mapped['temp_text'], ' '.join(f'{x:02X}' for x in plain)
            ])


def main():
    ap = argparse.ArgumentParser(description='Decode Meteotime payloads and assign region/section.')
    ap.add_argument('logfile')
    ap.add_argument('-n', '--limit', type=int, default=10)
    ap.add_argument('-v', '--verbose', action='store_true')
    ap.add_argument('--csv')
    args = ap.parse_args()

    rows = parse_rows(args.logfile)
    decoded = decode_log(rows, limit=args.limit)
    print(f'Rows: {len(rows)}')
    print(f'Decoded triplets: {len(decoded)}')
    print_decoded(decoded, show_internal=args.verbose)
    if args.csv:
        all_decoded = decode_log(rows, limit=None)
        write_csv(args.csv, all_decoded)
        print(f'CSV written: {args.csv} ({len(all_decoded)} records)')


if __name__ == '__main__':
    main()
