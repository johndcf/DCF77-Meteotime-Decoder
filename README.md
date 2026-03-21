# dcf77-meteotime-decoder
Decoding DCF77 Meteotime weather data (reverse engineering project)
DCF77 Meteotime Decoder

This project demonstrates how to decode Meteotime weather data transmitted via the DCF77 time signal (77.5 kHz).

Features
Full DCF77 Meteotime decoding
3-minute frame reconstruction
Decryption and validation (0x2501 check)
Extraction of weather data (temperature, conditions, wind)
Region and forecast mapping
How it works
Decode DCF77 bitstream
Assemble 3-minute frames
Build 82-bit buffer
Extract cipher and key
Decrypt payload
Validate using magic value
Interpret weather data
Example
Valid frame detected
Temperature: 12°C
Condition: Rain
Wind: Moderate
Disclaimer

This project is for educational and research purposes only.
It is not affiliated with, endorsed by, or connected to Meteotime or any related services.
