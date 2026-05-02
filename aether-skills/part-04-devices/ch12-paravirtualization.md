# SKILL.md — Chapter 12: The Necessity Of Paravirtualization

## Confidence Disclosure

**MEDIUM for sensor physics modeling, LOW for modem AT command protocol specifics, MEDIUM for USB bridge protocol design.** The three paravirtualized categories each require different domain knowledge. Sensor modeling requires understanding of MEMS physics. Modem simulation requires knowledge of AT command sets and 3GPP standards. Phone Bridge Mode requires USB protocol understanding.

## Required Primary Sources

**MEMS Sensor Physics:**

**"Random Signals and Noise" concepts** — any university-level signal processing textbook. The noise model for MEMS accelerometers follows an Allan deviation / power spectral density model documented in sensor datasheets.

**Bosch BMI160 Datasheet** — representative accelerometer/gyroscope datasheet, available at bosch-sensortec.com. Study the noise specifications (noise density in µg/√Hz and °/s/√Hz) and bias stability figures.

**InvenSense MPU-6500 Datasheet** — another common phone sensor, available at invensense.tdk.com. Different noise characteristics than BMI160.

**3GPP AT Command Set:**

**3GPP TS 27.007** — AT command set for User Equipment (UE). The authoritative specification for cellular modem AT commands. Available free at 3gpp.org. Critical sections: Chapter 7 (general commands), Chapter 8 (mobile termination control), Chapter 10 (GPRS commands).

**USB Protocol:**

**USB 3.2 Specification** — available at usb.org. For Phone Bridge Mode, relevant sections cover USB bulk transfer (for sensor streaming) and USB control transfer (for identity queries).

**Android Open Accessory Protocol** — developer.android.com. For the companion app on the phone side.

## Secondary Sources

**Android Sensor HAL interface** at `hardware/interfaces/sensors/` in AOSP — defines exactly what data format and timing the Android stack expects from sensor hardware.

**Android RIL (Radio Interface Layer)** at `hardware/ril/` in AOSP — defines the interface between Android's telephony stack and the modem. This is what AETHER's virtual modem must implement on the Android side.

**oFono** — open source telephony stack at ofono.org. Its modem abstraction layer is a reference for implementing modem AT command handling in software.

**Linux IIO (Industrial I/O) subsystem** at `drivers/iio/` in the kernel — the Linux kernel framework for sensors that the Android Common Kernel uses.

## Critical Concepts

**Physically Realistic Sensor Noise.** The critical property that distinguishes real sensor data from fake sensor data is the statistical distribution of the noise. A real accelerometer at rest doesn't read exactly (0, 0, 9.81) m/s². It reads something like (0.002, -0.003, 9.814) with a new tiny random offset every sample that follows a Gaussian distribution with a specific standard deviation. Over time, the noise has specific frequency characteristics described by its power spectral density. Anti-detection systems can run statistical tests on sensor data — checking for Gaussianity of the noise, checking the noise density against expected values for real sensors, checking for the absence of quantization artifacts. AETHER's sensor model must pass these tests.

The implementation uses a Gaussian random number generator (Box-Muller transform or similar) seeded with a hardware entropy source, scaled to the noise density of the target sensor (in the datasheet), and added to the ideal physical value. For the gyroscope, a first-order random walk model is added for bias drift. For the magnetometer, a fixed offset representing local magnetic declination plus noise.

**The Sensor Polling Rate Contract.** Android's Sensor HAL expects sensors to deliver data at specific polling intervals. The standard intervals are SENSOR_DELAY_FASTEST (~1ms), SENSOR_DELAY_GAME (~20ms), SENSOR_DELAY_UI (~60ms), SENSOR_DELAY_NORMAL (~200ms). AETHER's virtual sensor driver must deliver data at exactly the requested interval, because timing-based tests can detect sensors that deliver data at irregular or wrong intervals.

**AT Command Virtual Modem.** The Android RIL communicates with the modem through a serial interface (real or virtual) using AT commands. AETHER implements a virtual serial device that speaks the AT command set. The minimum commands that must be implemented for Android to consider the modem functional are: AT (echo test), ATI (identification — returns model and revision), AT+CGMI (manufacturer), AT+CGMM (model), AT+CGSN (IMEI), AT+CREG (network registration), AT+CGREG (GPRS registration), AT+COPS (operator selection), AT+CSQ (signal quality), AT+CMGF (message format), AT+CMGS (send message). The responses must follow 3GPP TS 27.007 format exactly.

**Phone Bridge Mode Protocol.** The AETHER companion app on the Android phone exposes a USB accessory interface. The protocol over USB is: identity queries use USB control transfers (low-latency, synchronous), sensor streaming uses USB bulk transfers (asynchronous, high-throughput), camera frames use USB isochronous transfers (guaranteed bandwidth). AETHER's host-side driver handles these transfer types and presents the received data to the Android partition's sensor and camera HALs as if they came from virtual local hardware.

## Common AI Mistakes In This Domain

Claude generates sensor noise using `rand()` or `random()` without proper Gaussian distribution shaping. Simple uniform random noise is trivially distinguishable from real sensor noise by its distribution shape.

Claude generates AT command responses that omit the final "OK" or "ERROR" response terminator, which causes the Android RIL to hang waiting for a response that never comes.

Claude generates sensor data at exact millisecond intervals. Real sensors have slight jitter in their delivery timing. Perfectly periodic sensor data is a detectable anomaly.

Claude models gyroscope drift as a constant rather than as a random walk, which produces drift that any statistical test would immediately reject.

## Verification Protocol

For sensor simulation:
1. Generate 10,000 samples from your accelerometer model at rest and compute the standard deviation — verify it matches the target sensor's noise density specification
2. Run a Kolmogorov-Smirnov test on the noise samples to verify Gaussianity
3. Compute Allan deviation on gyroscope output and verify bias instability matches the target sensor's datasheet

For AT command virtual modem:
1. Send each implemented AT command and verify the response format against 3GPP TS 27.007
2. Test that AT+CGSN returns the configured IMEI and that the IMEI passes Luhn checksum validation
3. Test modem state machine transitions (e.g., +CREG: 0 → +CREG: 1 on simulated network registration)

For Phone Bridge Mode:
1. Verify USB transfer type selection matches the data characteristics (control for queries, bulk for streaming)
2. Verify sensor data timing jitter when received over USB matches real sensor timing characteristics

## Pre-Flight Checklist

- [ ] Download BMI160 and MPU-6500 datasheets — study noise density tables carefully
- [ ] Read 3GPP TS 27.007 Chapter 7 and 8 (available free at 3gpp.org)
- [ ] Study Android Sensor HAL at `hardware/interfaces/sensors/` in AOSP source
- [ ] Study Android RIL at `hardware/ril/` in AOSP source
- [ ] Implement a test that generates 10,000 accelerometer samples and verifies their statistical properties before integrating into AETHER
- [ ] Test the virtual modem AT command sequence using `minicom` or `screen` connected to the virtual serial port before connecting Android's RIL
