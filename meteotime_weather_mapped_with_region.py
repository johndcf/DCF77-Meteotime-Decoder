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
#
# SEMANTIC MODEL NOTE:
# The section labels "Hoch" / "Tief" are kept internally for compatibility
# with older reasoning, but the output interpretation is now modeled as:
# - TAG-BLOCK:   12 h day weather + 12 h day temperature
#                plus 24 h heavy-weather / rain information
# - NACHT-BLOCK: 12 h night weather + 12 h night temperature
#                plus 24 h wind information
#
# In other words, the two sections are treated as two complementary views
# of one forecast day, not as two unrelated forecasts.
# ------------------------------------------------------------

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import re
from dataclasses import dataclass
from datetime import date
from typing import List, Optional

ENABLE_SECTION7_OVERRIDE = False

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
    0: "Kein", 1: "Schweres Wetter 24 Std.", 2: "Schweres Wetter (Tag)",
    3: "Schweres Wetter (Nacht)", 4: "Sturm", 5: "Sturm (Tag)",
    6: "Sturm (Nacht)", 7: "Böen (Tag)", 8: "Böen (Nacht)",
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
    26: "Bise NO",
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
    42: "Bise NO",
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
    58: "Bise NO",
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
    74: "Bise NO",
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
    90: "Bise NO",
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
    106: "Bise NO",
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
    122: "Bise NO",
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
    0: "Bordeaux / Südwestfrankreich",
    1: "La Rochelle / Westküste Frankreich",
    2: "Paris / Pariser Becken",
    3: "Brest / Bretagne",
    4: "Clermont-Ferrand / Zentralmassif",
    5: "Béziers / Languedoc-Roussillon",
    6: "Bruxelles / Benelux",
    7: "Dijon / Ostfrankreich (Burgund)",
    8: "Marseille / Südfrankreich",
    9: "Lyon / Rhonetal",
    10: "Grenoble / Französische Alpen",
    11: "La Chaux-de-Fonds / Jura",
    12: "Frankfurt am Main / Unterer Rheingraben",
    13: "Westl. Mittelgebirge / Westliches Mittelgebirge",
    14: "Duisburg / Nordrhein-Westfalen",
    15: "Swansea / Westl. England & Wales",
    16: "Manchester / Nördliches England",
    17: "Le Havre / Normandie",
    18: "London / Südostengland",
    19: "Bremerhaven / Nordseeküste",
    20: "Herning / Nordwestliches Jütland",
    21: "Århus / Östliches Jütland",
    22: "Hannover / Norddeutschland",
    23: "København / Seeland",
    24: "Rostock / Ostseeküste",
    25: "Ingolstadt / Donautal",
    26: "München / Südbayern",
    27: "Bolzano / Südtirol",
    28: "Nürnberg / Nordbayern",
    29: "Leipzig / Sachsen",
    30: "Erfurt / Thüringen",
    31: "Lausanne / Westliches Schweizer Mittelland",
    32: "Zürich / Östliches Schweizer Mittelland",
    33: "Adelboden / Westlicher Schweizer Alpennordhang",
    34: "Sion / Wallis",
    35: "Glarus / Östlicher Schweizer Alpennordhang",
    36: "Davos / Graubünden",
    37: "Kassel / Mittelgebirge Ost",
    38: "Locarno / Tessin",
    39: "Sestriere / Piemont Alpen",
    40: "Milano / Poebene",
    41: "Roma / Toskana",
    42: "Amsterdam / Holland",
    43: "Génova / Golf von Genua",
    44: "Venezia / Pomündung",
    45: "Strasbourg / Oberer Rheingraben",
    46: "Klagenfurt / Österreichischer Alpensüdhang",
    47: "Innsbruck / Inneralpine Gebiete Österreich",
    48: "Salzburg / Alpennordhang Bayern/Österreich",
    49: "Bratislava / Wien-Region (AT/SK)",
    50: "Praha / Tschechisches Becken",
    51: "Decin / Erzgebirge",
    52: "Berlin / Ostdeutschland",
    53: "Göteborg / Westküste Schweden",
    54: "Stockholm / Stockholm-Region",
    55: "Kalmar / Schwedische Ostseeküste",
    56: "Jönköping / Südschweden",
    57: "Donaueschingen / Schwarzwald & Schwäbische Alb",
    58: "Oslo / Oslo-Region",
    59: "Stuttgart / Nördliches Baden-Württemberg",
    60: "Napoli", 61: "Ancona", 62: "Bari", 63: "Budapest", 64: "Madrid",
    65: "Bilbao", 66: "Palermo", 67: "Palma de Mallorca", 68: "Valencia", 69: "Barcelona",
    70: "Andorra", 71: "Sevilla", 72: "Lissabon", 73: "Sassari", 74: "Gijon",
    75: "Galway", 76: "Dublin", 77: "Glasgow", 78: "Stavanger", 79: "Trondheim",
    80: "Sundsvall", 81: "Gdansk", 82: "Warszawa", 83: "Krakow", 84: "Umea",
    85: "Oestersund", 86: "Samedan", 87: "Zagreb", 88: "Zermatt", 89: "Split",
}
SECTION_INFO = {
    0: ("Heute", "Tag-Block", "12h Tag + 24h Schweres Wetter/Regen"),
    1: ("Heute", "Nacht-Block", "12h Nacht + 24h Wind"),
    2: ("Tag 1", "Tag-Block", "12h Tag + 24h Schweres Wetter/Regen"),
    3: ("Tag 1", "Nacht-Block", "12h Nacht + 24h Wind"),
    4: ("Tag 2", "Tag-Block", "12h Tag + 24h Schweres Wetter/Regen"),
    5: ("Tag 2", "Nacht-Block", "12h Nacht + 24h Wind"),
    6: ("Tag 3", "Tag-Block", "12h Tag + 24h Schweres Wetter/Regen"),
    7: ("ungenutzt", "ungenutzt", "ungenutzt"),
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
        'wind_direction_valid_when_anomaly_bit_is_0': True,
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

    # Meteotime send schema in UTC:
    # 22:00 - 03:59  regions 0..59  -> Heute   (sections 0/1, 6 min per region)
    # 04:00 - 09:59  regions 0..59  -> Tag 1   (sections 2/3, 6 min per region)
    # 10:00 - 15:59  regions 0..59  -> Tag 2   (sections 4/5, 6 min per region)
    # 16:00 - 18:59  regions 0..59  -> Tag 3   (section 6 only, 3 min per region)
    # 19:00 - 20:29  regions 60..89 -> Heute   (2-day model, HI only)
    # 20:30 - 21:59  regions 60..89 -> Tag 1   (2-day model, HI only)

    if 0 <= minutes <= 179:          # 22:00 - 00:59 UTC
        area = minutes // 3
        section = 0
    elif 180 <= minutes <= 359:      # 01:00 - 03:59 UTC
        area = (minutes - 180) // 3
        section = 1
    elif 360 <= minutes <= 539:      # 04:00 - 06:59 UTC
        area = (minutes - 360) // 3
        section = 2
    elif 540 <= minutes <= 719:      # 07:00 - 09:59 UTC
        area = (minutes - 540) // 3
        section = 3
    elif 720 <= minutes <= 899:      # 10:00 - 12:59 UTC
        area = (minutes - 720) // 3
        section = 4
    elif 900 <= minutes <= 1079:     # 13:00 - 15:59 UTC
        area = (minutes - 900) // 3
        section = 5
    elif 1080 <= minutes <= 1259:    # 16:00 - 18:59 UTC
        area = (minutes - 1080) // 3
        section = 6
    elif 1260 <= minutes <= 1349:    # 19:00 - 20:29 UTC
        area = 60 + ((minutes - 1260) // 3)
        section = 0
    else:                            # 20:30 - 21:59 UTC
        area = 60 + ((minutes - 1350) // 3)
        section = 1

    return area, section

def add_region_section(mapped: dict, row: Row):
    area, section = get_area_section(row)
    region_name, forecast_days = get_region_meta(area)

    mapped['region_id'] = area
    mapped['region_name'] = region_name
    mapped['forecast_days'] = forecast_days
    mapped['section_id'] = section

    # Regions 60..89 use a reduced 2-day forecast model:
    # one 90-minute block for today and one 90-minute block for the following day.
    # Only day/night weather and one HI temperature are shown.
    if area >= 60:
        day_label = 'Heute' if section == 0 else 'Tag 1'
        section_kind = '2-Tages-Prognose'
        interpretation = 'nur Wetter Tag/Nacht + Temperatur (HI)'

        mapped['day_label'] = day_label
        mapped['section_kind'] = section_kind
        mapped['interpretation'] = interpretation
        mapped['is_high_section'] = False
        mapped['is_low_wind_section'] = False
        mapped['section7_high_override'] = False
        mapped['display_day_weather'] = mapped['day_weather']
        mapped['display_day_code'] = mapped['day_code']
        mapped['display_night_weather'] = mapped['night_weather']
        mapped['display_night_code'] = mapped['night_code']
        mapped['section_value_text'] = '-'
        mapped['temp_text'] = f"{mapped['temp_text']} (HI)"
        return mapped

    day_label, section_kind, interpretation = SECTION_INFO.get(section, (f'Sektion {section}', '?', '?'))
    mapped['day_label'] = day_label
    mapped['section_kind'] = section_kind
    mapped['interpretation'] = interpretation
    mapped['is_high_section'] = section in (0, 2, 4, 6)
    mapped['is_low_wind_section'] = section in (1, 3, 5, 7)
    mapped['section7_high_override'] = (
     ENABLE_SECTION7_OVERRIDE and section == 7 and mapped['anomaly_bit'] == 0
)

    if mapped['is_high_section'] or mapped['section7_high_override']:
        mapped['display_day_weather'] = mapped['day_weather']
        mapped['display_day_code'] = mapped['day_code']
        mapped['display_night_weather'] = mapped['night_weather']
        mapped['display_night_code'] = mapped['night_code']

        # The Bit-15 anomaly interpretation for "Tag" is only valid for
        # section 0 (Heute / Hoch). For forecast days (sections 2/4/6),
        # Bit 15 is treated as not applicable and the block is always
        # interpreted as extreme weather + rain. This makes the decoder
        # more robust against occasional bit errors in later high sections.
        mapped['day_anomaly_mode_valid'] = (section == 0)

        if mapped['anomaly_bit'] == 1 and mapped['day_anomaly_mode_valid']:
            mapped['section_value_text'] = (
                f"Relatives Vormittagswetter = {mapped['morning_jump_text']} (Code {mapped['morning_jump_code']}), "
                f"Sonnenscheindauer = {mapped['sunshine_text']} (Code {mapped['sunshine_code']}), "
                f"Regen = {mapped['rain_percent']} %"
            )
        else:
            mapped['section_value_text'] = (
                f"Schweres Wetter = {mapped['extreme_text']} (Code {mapped['extreme_code']}), "
                f"Regen = {mapped['rain_percent']} %"
            )
    else:
        mapped['display_day_weather'] = mapped['day_weather']
        mapped['display_day_code'] = mapped['day_code']
        mapped['display_night_weather'] = mapped['night_weather']
        mapped['display_night_code'] = mapped['night_code']

        if mapped['anomaly_bit'] == 0:
            mapped['section_value_text'] = (
                f"Wind = {mapped['wind_direction']} (Code {mapped['wind_dir_code']}), "
                f"Stärke = {mapped['wind_force']} (Code {mapped['wind_force_code']})"
            )
        else:
            mapped['section_value_text'] = (
                f"Schweres Wetter = {mapped['extreme_text']} (Code {mapped['extreme_code']})"
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
        if mapped['display_day_code'] is None:
            print(f"  Tag:      {mapped['display_day_weather']}")
        else:
            print(f"  Tag:      {mapped['display_day_weather']} (Code {mapped['display_day_code']})")
        if mapped['display_night_code'] is None:
            print(f"  Nacht:    {mapped['display_night_weather']}")
        else:
            print(f"  Nacht:    {mapped['display_night_weather']} (Code {mapped['display_night_code']})")
        print(f'  Temp:     {mapped["temp_text"]} (Code {mapped["temp_code"]})')
        print(f'  Anom.:    {mapped["anomaly_bit"]}')
        if mapped.get('is_low_wind_section') and not mapped.get('section7_high_override'):
            if mapped['anomaly_bit'] == 0:
                print(f'  Wind:     {mapped["wind_direction"]}, Stärke {mapped["wind_force"]} (Code {mapped["wind_full_code"]}, dir={mapped["wind_dir_code"]}, force={mapped["wind_force_code"]})')
            else:
                print(f'  Wind:     -')
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
            'date', 'time', 'region_id', 'region_name', 'forecast_days', 'section_id', 'day_label', 'section_kind', 'block_role', 'temperature_role',
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
                mapped['region_id'], mapped['region_name'], mapped['forecast_days'], mapped['section_id'], mapped['day_label'], mapped['section_kind'], mapped.get('block_role'), mapped.get('temperature_role'),
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
