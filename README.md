# DCF77 Meteotime Decoder

![Python](https://img.shields.io/badge/Python-3.x-blue)
![DCF77](https://img.shields.io/badge/Signal-DCF77-orange)
![Meteotime](https://img.shields.io/badge/Data-Meteotime-blueviolet)
![Reverse Engineering](https://img.shields.io/badge/type-reverse--engineering-red)
![Status](https://img.shields.io/badge/status-research-green)
![License](https://img.shields.io/badge/license-MIT-blue)

---

## 📡 Overview

This project demonstrates how to decode **Meteotime weather data** transmitted via the **DCF77 time signal (77.5 kHz)**.

It reconstructs the full decoding chain:

* Bitstream acquisition
* 3-minute frame assembly
* Decryption and validation
* Weather data extraction and interpretation

👉 Result:
From raw RF signal to **human-readable weather data**

---

## ✨ Features

* Full Meteotime decoding implementation
* Correct 3-minute frame reconstruction
* 82-bit buffer handling (weather + time)
* Decryption with time-derived key
* Validation using **0x2501 magic check**
* Extraction of:

  * Temperature
  * Weather conditions
  * Wind / rain information
* Region and forecast mapping

---

## ⚙️ How It Works

1. Decode DCF77 bitstream (pulse length → bits)
2. Assemble 3-minute Meteotime frames
3. Build 82-bit data buffer
4. Extract cipher and key
5. Decrypt payload
6. Validate result (0x2501)
7. Interpret weather data

---

## 📦 Data Structure

Meteotime data is transmitted in **3-minute frames**:

* Minute n: 14 payload bits
* Minute n+1: 8 payload bits + 6 check bits
* Minute n+2: 14 check bits

👉 Total: **42-bit block per dataset**

---

## 🔐 Encryption

* Substitution-based cipher (S-Boxes)
* Bit permutations
* Key derived from time/date
* No key transmitted

👉 A lightweight broadcast cryptosystem

---

## 📊 Example Output

```text
Valid frame detected
Temperature: 12°C
Condition: Rain
Wind: Moderate
Region: Central Europe
```

---

## 🧠 Background

Meteotime has long been considered difficult to decode due to:

* Missing official documentation
* Encrypted data format
* Complex framing

This project shows that with:

* Real signal recordings
* Public reference implementations
* Iterative analysis

👉 Full decoding becomes possible.

---

## ⚠️ Legal Notice

Meteotime is a commercial service and its data format may be subject to intellectual property rights.

This project is intended for **educational and research purposes only**.
It demonstrates the decoding of publicly received DCF77 signals.

The author is not affiliated with, endorsed by, or connected to Meteotime or any related services.

Any use of this project is at your own responsibility.

This project must not be used for commercial purposes.

---


