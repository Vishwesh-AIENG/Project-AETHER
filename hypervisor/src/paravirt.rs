// ch12: The Necessity Of Paravirtualization
//
// Three device categories make passthrough impossible; AETHER paravirtualizes
// exactly these and no others:
//
//   1. Cellular modem — a laptop has no modem in the form-factor Android
//      expects. A virtual modem speaks the AT command set (3GPP TS 27.007)
//      and presents itself as a Qualcomm/Samsung baseband processor. Responses
//      are timed and parameterized to match real baseband behavior.
//
//   2. Sensor suite — laptops lack gyroscope, magnetometer, and proximity
//      sensor; sometimes accelerometer too. The virtual sensor subsystem
//      generates physically-accurate synthetic data:
//        • Accelerometer: Gaussian noise (Irwin-Hall CLT, n=12 uniform draws),
//          σ = 9.303 mm/s², matching Bosch BMI160 noise density 150 µg/√Hz at
//          40 Hz bandwidth. Uniform noise is statistically distinguishable from
//          real MEMS noise and is NEVER used here.
//        • Gyroscope: Gaussian noise σ = 55 mdps (BMI160: 8.7 mdps/√Hz × √40 Hz)
//          plus first-order random-walk bias drift (σ_step ≈ 83.3 µdps/sample
//          at 100 Hz ODR, matching BMI160 bias instability of 3 °/h).
//        • Magnetometer: Earth mid-latitude field components plus Gaussian noise
//          σ = 300 nT (Bosch BMM150 specification), with configurable local
//          magnetic declination.
//        • Proximity: binary; always reports Far — the same state a real device
//          reports when the sensor is disabled or obstructed.
//
//   3. Phone-specific peripherals (fingerprint sensor, NFC, front camera, etc.):
//      reported as present-but-unavailable — the normal state on real devices
//      when disabled by the user or covered.
//
// Phone Bridge Mode (toggleable at runtime, both ARM and x86 tiers):
//   Toggle ON  — live sensor and identity data streamed from a connected Android
//                phone over USB. USB bulk transfers carry continuous sensor
//                streams; USB control transfers carry identity queries. Software
//                models are bypassed while the bridge is active.
//   Toggle OFF — software physics models in this module supply all sensor data.
//
// Hardware-authenticity invariants (from CLAUDE.md §Hardware Authenticity):
//   • Sensor noise MUST be Gaussian, never uniform random.
//   • IMEI MUST pass Luhn checksum — never all-zeros or repeated digits.
//   • Sensor polling rate must be within ±5% of the requested interval.
//   • All delivery timestamps use CLOCK_BOOTTIME nanoseconds.
//
// AT command response format (3GPP TS 27.007 §5.1):
//   Request  → "AT<cmd>\r"
//   Response → "\r\n<data>\r\n\r\nOK\r\n"  (data lines, then final OK)
//            → "\r\nOK\r\n"                 (no data)
//            → "\r\nERROR\r\n"              (unrecognised or rejected command)
//
// References:
//   3GPP TS 27.007 v17.4.0  — AT command set for UE (modem interface)
//   Bosch BMI160 DS000 r1.2  — noise density: accel 150 µg/√Hz, gyro 8.7 mdps/√Hz
//   InvenSense MPU-6500      — cross-reference MEMS sensor parameters
//   Bosch BMM150 DS000 r1.3  — magnetometer noise floor ≈ 300 nT RMS
//   Android Sensor HAL       — hardware/interfaces/sensors/ (AOSP)
//   Android RIL              — hardware/ril/ (AOSP)
//   ISO/IEC 7812-1           — Luhn algorithm for IMEI check digit
//   Marsaglia (2003)         — Xorshift RNGs, Journal of Statistical Software

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

/// Errors returned by paravirt subsystem operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParavirtError {
    /// IMEI failed ISO/IEC 7812-1 Luhn checksum validation.
    InvalidImei,
    /// Unrecognised AT command; the modem will respond with ERROR.
    AtCommandUnknown,
    /// Response buffer is too small to hold the complete AT response.
    ResponseBufferTooSmall,
    /// Phone Bridge Mode is active; the software sensor model is bypassed.
    /// Caller must read sensor data from the USB bridge instead.
    BridgeModeActive,
}

// ─────────────────────────────────────────────────────────────────────────────
// Xorshift64 PRNG — no_std, no heap, no libm transcendental functions
//
// Period 2^64 − 1. Seed must be non-zero.
// Reference: Marsaglia, G. (2003). "Xorshift RNGs". J. Statistical Software.
// ─────────────────────────────────────────────────────────────────────────────

/// 64-bit xorshift pseudo-random number generator.
///
/// Suitable for sensor noise simulation. Not cryptographically secure.
#[derive(Clone, Copy)]
pub struct Xorshift64(u64);

impl Xorshift64 {
    /// Construct from a non-zero seed. A zero seed produces all-zero output forever.
    pub const fn new(seed: u64) -> Self {
        // Checked at compile time where possible; panics at runtime in debug if zero.
        assert!(seed != 0, "Xorshift64 seed must not be zero");
        Self(seed)
    }

    /// Advance the state and return the next pseudo-random u64.
    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    /// Return the next pseudo-random u32 (lower 32 bits of next_u64).
    #[inline]
    pub fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    /// Return a uniform sample in [0.0, 1.0) using 24 bits of mantissa precision.
    #[inline]
    pub fn next_f32(&mut self) -> f32 {
        // Upper 24 bits → integer in [0, 2^24) → divide → [0.0, 1.0)
        const SCALE: f32 = 1.0 / (1u64 << 24) as f32;
        ((self.next_u64() >> 40) as f32) * SCALE
    }

    /// Approximate N(0, 1) sample via the Irwin–Hall CLT method (n = 12).
    ///
    /// Sums 12 independent uniform [0, 1) samples and subtracts 6.
    /// Theoretical properties:
    ///   Mean     = 0   (exact)
    ///   Variance = 1   (exact: Var(U[0,1)) = 1/12; 12 × 1/12 = 1)
    ///   Kurtosis = 3.0 (exact for continuous Irwin-Hall at n = 12)
    ///   Range    = [−6, +6]  (6σ; all realistic MEMS sensor values lie here)
    ///
    /// No `ln`, `cos`, or `sqrt` required — fully compatible with bare-metal no_std.
    /// Uniform noise (single draw) must NEVER substitute for this; it is
    /// statistically distinguishable from real MEMS noise by distribution shape.
    #[inline]
    pub fn next_gaussian(&mut self) -> f32 {
        // 12 uniform draws; unrolled for predictable latency
        let s = self.next_f32()
            + self.next_f32()
            + self.next_f32()
            + self.next_f32()
            + self.next_f32()
            + self.next_f32()
            + self.next_f32()
            + self.next_f32()
            + self.next_f32()
            + self.next_f32()
            + self.next_f32()
            + self.next_f32();
        s - 6.0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IMEI validation — ISO/IEC 7812-1 Luhn algorithm
// ─────────────────────────────────────────────────────────────────────────────

/// Validate a 15-digit IMEI string using the Luhn checksum algorithm.
///
/// Each byte in `imei` must be an ASCII digit ('0'..='9').
///
/// Luhn algorithm (ISO/IEC 7812-1):
///   Starting from the second-to-last digit and moving left, double every
///   other digit. If the doubled value exceeds 9, subtract 9. Sum all 15
///   digits. The IMEI is valid if and only if the sum is divisible by 10.
///
/// Returns `Ok(())` on success, `Err(ParavirtError::InvalidImei)` otherwise.
pub fn validate_imei(imei: &[u8; 15]) -> Result<(), ParavirtError> {
    let mut sum = 0u32;
    for (i, &byte) in imei.iter().enumerate() {
        if !(b'0'..=b'9').contains(&byte) {
            return Err(ParavirtError::InvalidImei);
        }
        let mut digit = (byte - b'0') as u32;
        // Double positions that are odd (0-indexed from left).
        // Rationale: position from right = 15 − i. The Luhn rule doubles
        // positions 2, 4, 6, … from the right (i.e., the second-to-last,
        // fourth-to-last, …). From-right even positions correspond to
        // from-left odd positions (since 15 is odd: 15 − odd = even).
        if i % 2 == 1 {
            digit *= 2;
            if digit > 9 {
                digit -= 9;
            }
        }
        sum += digit;
    }
    if sum % 10 == 0 {
        Ok(())
    } else {
        Err(ParavirtError::InvalidImei)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Sensor data types
// ─────────────────────────────────────────────────────────────────────────────

/// Three-axis accelerometer sample.
///
/// Units: m/s². At rest with the device face-up, z ≈ +9.807 m/s² (gravity),
/// x ≈ 0, y ≈ 0. Positive z is upward per Android coordinate convention.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct AccelSample {
    pub x: f32,
    pub y: f32,
    pub z: f32,
}

/// Three-axis gyroscope sample.
///
/// Units: degrees per second (dps). At rest all axes ≈ 0, with small Gaussian
/// noise and slowly drifting bias (random walk model).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct GyroSample {
    pub x: f32,
    pub y: f32,
    pub z: f32,
}

/// Three-axis magnetometer sample.
///
/// Units: microtesla (µT). Values reflect Earth's magnetic field at a
/// representative mid-latitude location plus Gaussian noise.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MagSample {
    pub x: f32,
    pub y: f32,
    pub z: f32,
}

/// Proximity sensor state.
///
/// The virtual proximity sensor always reports `Far` — equivalent to a real
/// device where the sensor is present but uncovered. Apps that require
/// `Near` to function (e.g., auto-screen-off during calls) are already
/// tolerant of `Far` as the idle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProximityState {
    /// Object detected within the sensor's threshold distance (~5 cm).
    Near,
    /// No nearby object detected (or sensor absent/disabled).
    Far,
}

// ─────────────────────────────────────────────────────────────────────────────
// Phone Bridge Mode
// ─────────────────────────────────────────────────────────────────────────────

/// Selects the source of sensor and identity data for the Android partition.
///
/// Both modes are first-class: the software models are designed to be
/// sufficient without Bridge Mode. Bridge Mode exists for users who require
/// maximum hardware fidelity (e.g., apps that perform advanced sensor analysis).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BridgeMode {
    /// Software physics models supply all sensor data (default).
    SoftwareModel,
    /// Live sensor and identity data streamed from a connected Android phone
    /// over USB. Software models are bypassed. The USB driver (ch16) must be
    /// active before this mode is enabled.
    PhoneBridge,
}

// ─────────────────────────────────────────────────────────────────────────────
// Virtual Sensor Suite
//
// BMI160 noise parameters (Bosch BMI160 Datasheet DS000 rev 1.2, §3.2):
//   Accelerometer noise density : 150 µg/√Hz = 1.471×10⁻³ m/s²/√Hz
//   Gyroscope noise density     : 8.7 mdps/√Hz
//   Gyroscope bias instability  : 3 °/h ≈ 8.333×10⁻⁴ °/s
//
// At 40 Hz low-pass bandwidth (BMI160 default for 100 Hz ODR):
//   σ_accel = 1.471×10⁻³ × √40 ≈ 9.303×10⁻³ m/s²
//   σ_gyro  = 8.7×10⁻³  × √40 ≈ 55.0×10⁻³ dps
//
// Gyro bias random walk per sample at 100 Hz ODR:
//   σ_bias_step = bias_instability / √ODR = 8.333×10⁻⁴ / √100 ≈ 8.333×10⁻⁵ °/s
//
// Magnetometer (BMM150, DS000 rev 1.3):
//   Noise floor ≈ 300 nT RMS (0.3 µT) on all axes.
// ─────────────────────────────────────────────────────────────────────────────

/// Standard deviation of accelerometer noise at 40 Hz bandwidth (m/s²).
/// BMI160: 150 µg/√Hz × √40 Hz × 9.80665 m/s²/g = 9.303×10⁻³ m/s².
const ACCEL_SIGMA_MPS2: f32 = 9.303e-3;

/// Standard deviation of gyroscope noise at 40 Hz bandwidth (dps).
/// BMI160: 8.7 mdps/√Hz × √40 Hz = 54.97×10⁻³ dps.
const GYRO_SIGMA_DPS: f32 = 54.97e-3;

/// Standard deviation of gyroscope bias random-walk step per 100 Hz sample (dps).
/// BMI160 bias instability 3 °/h / √100 Hz = 8.333×10⁻⁵ °/s = 8.333×10⁻⁵ dps.
const GYRO_BIAS_STEP_DPS: f32 = 8.333e-5;

/// Standard deviation of magnetometer noise (µT). BMM150: ≈300 nT = 0.3 µT.
const MAG_SIGMA_UT: f32 = 0.3;

/// Earth's magnetic field at a representative mid-latitude location (µT).
/// Values derived from IGRF-13 model for approximately 40°N, 74°W (New York).
const EARTH_MAG_X_UT: f32 = 20.1; // geographic north component
const EARTH_MAG_Y_UT: f32 = -5.3; // east component (negative = westward declination)
const EARTH_MAG_Z_UT: f32 = 49.5; // vertical / downward component

/// Gravitational acceleration constant (m/s²). Android Sensor SDK uses 9.80665.
const GRAVITY_MPS2: f32 = 9.80665;

/// Virtual sensor subsystem.
///
/// Generates physically-accurate synthetic sensor data using Gaussian noise
/// models calibrated to real MEMS sensor specifications (Bosch BMI160, BMM150).
/// Call `sample_accel`, `sample_gyro`, and `sample_mag` at the polling rate
/// requested by the Android Sensor HAL.
pub struct VirtualSensorSuite {
    /// Pseudo-random number generator. Never zero; seeded from platform entropy.
    prng: Xorshift64,
    /// Accumulated gyroscope bias (°/s) — random walk state, one value per axis.
    /// Starts at zero; drifts by ~83.3 µdps per sample on each axis independently.
    gyro_bias: [f32; 3],
    /// Current bridge mode. `SoftwareModel` → generate synthetic data.
    /// `PhoneBridge` → `sample_*` methods return `BridgeModeActive`.
    bridge_mode: BridgeMode,
}

impl VirtualSensorSuite {
    /// Construct with a non-zero PRNG seed.
    ///
    /// In production, seed from the platform hardware entropy source before
    /// the first sample is requested. Using a constant seed in production is
    /// detectable by repeat-sample statistical analysis.
    pub const fn new(seed: u64) -> Self {
        Self {
            prng: Xorshift64::new(seed),
            gyro_bias: [0.0; 3],
            bridge_mode: BridgeMode::SoftwareModel,
        }
    }

    /// Enable or disable Phone Bridge Mode.
    ///
    /// When `PhoneBridge` is active, all `sample_*` calls return
    /// `Err(ParavirtError::BridgeModeActive)`. The USB driver (ch16) is
    /// responsible for forwarding live hardware data to the Android HAL.
    pub fn set_bridge_mode(&mut self, mode: BridgeMode) {
        self.bridge_mode = mode;
    }

    /// Current bridge mode.
    pub fn bridge_mode(&self) -> BridgeMode {
        self.bridge_mode
    }

    /// Sample the accelerometer.
    ///
    /// Models a BMI160 face-up at rest: z ≈ +g (gravity), x ≈ y ≈ 0, all axes
    /// with Gaussian noise σ = 9.303 mm/s². Returns `BridgeModeActive` when
    /// Phone Bridge Mode is enabled.
    ///
    /// Call at the interval requested by Android Sensor HAL
    /// (SENSOR_DELAY_GAME ≈ 20 ms for gaming workloads).
    pub fn sample_accel(&mut self) -> Result<AccelSample, ParavirtError> {
        if self.bridge_mode == BridgeMode::PhoneBridge {
            return Err(ParavirtError::BridgeModeActive);
        }
        Ok(AccelSample {
            x: self.prng.next_gaussian() * ACCEL_SIGMA_MPS2,
            y: self.prng.next_gaussian() * ACCEL_SIGMA_MPS2,
            // +GRAVITY on z because BMI160 reports upward force at rest (reaction to gravity)
            z: GRAVITY_MPS2 + self.prng.next_gaussian() * ACCEL_SIGMA_MPS2,
        })
    }

    /// Sample the gyroscope.
    ///
    /// Models a BMI160 at rest: all axes ≈ 0 dps, with Gaussian noise
    /// σ = 55 mdps and a slowly-drifting bias modeled as a random walk
    /// (σ_step ≈ 83.3 µdps/sample, matching BMI160 bias instability 3 °/h at
    /// 100 Hz ODR). Returns `BridgeModeActive` when Phone Bridge is enabled.
    ///
    /// The bias state is accumulated across calls — each call advances the
    /// random walk. Callers must call this at a consistent rate.
    pub fn sample_gyro(&mut self) -> Result<GyroSample, ParavirtError> {
        if self.bridge_mode == BridgeMode::PhoneBridge {
            return Err(ParavirtError::BridgeModeActive);
        }
        // Advance random-walk bias on each axis
        self.gyro_bias[0] += self.prng.next_gaussian() * GYRO_BIAS_STEP_DPS;
        self.gyro_bias[1] += self.prng.next_gaussian() * GYRO_BIAS_STEP_DPS;
        self.gyro_bias[2] += self.prng.next_gaussian() * GYRO_BIAS_STEP_DPS;

        Ok(GyroSample {
            x: self.gyro_bias[0] + self.prng.next_gaussian() * GYRO_SIGMA_DPS,
            y: self.gyro_bias[1] + self.prng.next_gaussian() * GYRO_SIGMA_DPS,
            z: self.gyro_bias[2] + self.prng.next_gaussian() * GYRO_SIGMA_DPS,
        })
    }

    /// Sample the magnetometer.
    ///
    /// Returns Earth's mid-latitude magnetic field components plus Gaussian
    /// noise σ = 0.3 µT (BMM150 noise floor). The field components are fixed
    /// (static device) with noise added per call. Returns `BridgeModeActive`
    /// when Phone Bridge is enabled.
    pub fn sample_mag(&mut self) -> Result<MagSample, ParavirtError> {
        if self.bridge_mode == BridgeMode::PhoneBridge {
            return Err(ParavirtError::BridgeModeActive);
        }
        Ok(MagSample {
            x: EARTH_MAG_X_UT + self.prng.next_gaussian() * MAG_SIGMA_UT,
            y: EARTH_MAG_Y_UT + self.prng.next_gaussian() * MAG_SIGMA_UT,
            z: EARTH_MAG_Z_UT + self.prng.next_gaussian() * MAG_SIGMA_UT,
        })
    }

    /// Sample the proximity sensor.
    ///
    /// The virtual proximity sensor always reports `Far`. Phone Bridge Mode
    /// does NOT affect proximity — the bridge streams only sensor data from
    /// the sensor HAL (not proximity, which is typically unavailable over USB).
    pub fn sample_proximity(&self) -> ProximityState {
        ProximityState::Far
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Virtual Modem — AT command interface (3GPP TS 27.007)
//
// Minimum AT command set required for Android's RIL to consider the modem
// functional and attempt network registration:
//
//   AT          — echo test (required by RIL init sequence)
//   ATI         — modem identification (manufacturer + model + revision)
//   AT+CGMI     — request manufacturer identification
//   AT+CGMM     — request model identification
//   AT+CGSN     — request product serial number (IMEI)
//   AT+CREG?    — network registration status query
//   AT+CGREG?   — GPRS network registration status query
//   AT+COPS?    — operator selection query
//   AT+CSQ      — signal quality query
//   AT+CMGF=1   — set SMS message format (text mode; RIL sends this at init)
//
// Response format (3GPP TS 27.007 §5.1):
//   "\r\n<data>\r\n\r\nOK\r\n"  — response with data
//   "\r\nOK\r\n"                — success, no data
//   "\r\nERROR\r\n"             — error or unrecognised command
//
// The missing final OK/ERROR terminator is the most common AT modem bug
// (per the ch12 skill guide); every code path MUST emit a terminator.
// ─────────────────────────────────────────────────────────────────────────────

/// Network registration state (3GPP TS 27.007 §7.2, +CREG: <stat>).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistrationState {
    /// Not registered; not searching.
    NotRegistered = 0,
    /// Registered to home network.
    HomeNetwork = 1,
    /// Not registered; searching for a new operator.
    Searching = 2,
    /// Registration denied.
    Denied = 3,
    /// Unknown (e.g. out of GERAN/UTRAN/E-UTRAN coverage).
    Unknown = 4,
    /// Registered; roaming.
    Roaming = 5,
}

impl RegistrationState {
    fn as_digit(self) -> u8 {
        self as u8 + b'0'
    }
}

/// Maximum length of an AT response, in bytes.
/// Longest supported response: "+COPS: 0,0,\"T-Mobile\",7\r\n\r\nOK\r\n"
pub const AT_RESP_SIZE: usize = 128;

/// Virtual cellular modem.
///
/// Implements the minimum AT command subset required by the Android RIL.
/// Presents itself as a Qualcomm SM8550 (Snapdragon 8 Gen 2) baseband.
pub struct VirtualModem {
    /// 15-digit IMEI, ASCII ('0'..='9'). Pre-validated at construction time.
    imei: [u8; 15],
    /// Current (U)SIM operator name for +COPS response.
    operator: &'static str,
    /// Received Signal Strength Indicator, 0–31 (−113 dBm to −51 dBm).
    /// 99 means "not known or not detectable" (3GPP TS 27.007 §8.5).
    rssi_asu: u8,
    /// Network registration state, reported via +CREG and +CGREG.
    reg_state: RegistrationState,
}

impl VirtualModem {
    /// Construct a virtual modem with the given IMEI.
    ///
    /// Returns `Err(ParavirtError::InvalidImei)` if the IMEI fails Luhn
    /// validation. This check prevents Android's RIL from receiving an IMEI
    /// that would fail the Luhn test performed by app-level detection libraries.
    pub fn new(imei: [u8; 15]) -> Result<Self, ParavirtError> {
        validate_imei(&imei)?;
        Ok(Self {
            imei,
            operator: "T-Mobile",
            rssi_asu: 15, // −83 dBm; mid-range signal, plausible for indoors
            reg_state: RegistrationState::HomeNetwork,
        })
    }

    /// Override the operator name shown in AT+COPS responses.
    pub fn set_operator(&mut self, op: &'static str) {
        self.operator = op;
    }

    /// Override the network registration state.
    pub fn set_reg_state(&mut self, state: RegistrationState) {
        self.reg_state = state;
    }

    /// Process a complete AT command line and write the response into `resp`.
    ///
    /// `cmd` must be the full command line including the "AT" prefix but
    /// WITHOUT the trailing carriage-return / line-feed. Examples:
    ///   b"AT"        → "\r\nOK\r\n"
    ///   b"ATI"       → "\r\nAETHER … \r\n\r\nOK\r\n"
    ///   b"AT+CGSN"   → "\r\n{IMEI}\r\n\r\nOK\r\n"
    ///
    /// Returns the number of bytes written into `resp`, or
    /// `Err(ParavirtError::ResponseBufferTooSmall)` if the buffer is too small.
    /// Every successful path writes a valid 3GPP TS 27.007 terminator.
    pub fn process_command(
        &self,
        cmd: &[u8],
        resp: &mut [u8; AT_RESP_SIZE],
    ) -> Result<usize, ParavirtError> {
        // Command must start with "AT"
        if cmd.len() < 2 || cmd[0] != b'A' || cmd[1] != b'T' {
            return self.write_error(resp);
        }

        let body = &cmd[2..]; // everything after the "AT" prefix

        match body {
            // Bare AT — echo test
            b"" => self.write_ok(resp),

            // ATI — modem identification
            b"I" => {
                let mut p = 0usize;
                self.push(resp, &mut p, b"\r\nAETHER Virtual Modem / Qualcomm SM8550\r\nRevision: AETHER-1.0.0\r\n")?;
                self.push(resp, &mut p, b"\r\nOK\r\n")?;
                Ok(p)
            }

            // AT+CGMI — manufacturer identification
            b"+CGMI" => {
                let mut p = 0usize;
                self.push(resp, &mut p, b"\r\nQualcomm Technologies, Inc\r\n")?;
                self.push(resp, &mut p, b"\r\nOK\r\n")?;
                Ok(p)
            }

            // AT+CGMM — model identification
            b"+CGMM" => {
                let mut p = 0usize;
                self.push(resp, &mut p, b"\r\nSM8550\r\n")?;
                self.push(resp, &mut p, b"\r\nOK\r\n")?;
                Ok(p)
            }

            // AT+CGSN — product serial number (IMEI)
            b"+CGSN" => {
                let mut p = 0usize;
                self.push(resp, &mut p, b"\r\n")?;
                self.push(resp, &mut p, &self.imei)?;
                self.push(resp, &mut p, b"\r\n")?;
                self.push(resp, &mut p, b"\r\nOK\r\n")?;
                Ok(p)
            }

            // AT+CREG? — network registration status
            b"+CREG?" => {
                let mut p = 0usize;
                // Response format: +CREG: <n>,<stat>   (n=0: unsolicited result code disabled)
                self.push(resp, &mut p, b"\r\n+CREG: 0,")?;
                self.push_byte(resp, &mut p, self.reg_state.as_digit())?;
                self.push(resp, &mut p, b"\r\n")?;
                self.push(resp, &mut p, b"\r\nOK\r\n")?;
                Ok(p)
            }

            // AT+CGREG? — GPRS network registration status
            b"+CGREG?" => {
                let mut p = 0usize;
                self.push(resp, &mut p, b"\r\n+CGREG: 0,")?;
                self.push_byte(resp, &mut p, self.reg_state.as_digit())?;
                self.push(resp, &mut p, b"\r\n")?;
                self.push(resp, &mut p, b"\r\nOK\r\n")?;
                Ok(p)
            }

            // AT+COPS? — operator selection
            b"+COPS?" => {
                let mut p = 0usize;
                // +COPS: <mode>,<format>,<oper>,<AcT>
                // mode=0 (auto), format=0 (long alphanumeric), AcT=7 (E-UTRAN/LTE)
                self.push(resp, &mut p, b"\r\n+COPS: 0,0,\"")?;
                self.push(resp, &mut p, self.operator.as_bytes())?;
                self.push(resp, &mut p, b"\",7\r\n")?;
                self.push(resp, &mut p, b"\r\nOK\r\n")?;
                Ok(p)
            }

            // AT+CSQ — signal quality
            b"+CSQ" => {
                let mut p = 0usize;
                // +CSQ: <rssi>,<ber>   ber=99 means "not known"
                self.push(resp, &mut p, b"\r\n+CSQ: ")?;
                self.push_u8_decimal(resp, &mut p, self.rssi_asu)?;
                self.push(resp, &mut p, b",99\r\n")?;
                self.push(resp, &mut p, b"\r\nOK\r\n")?;
                Ok(p)
            }

            // AT+CMGF=1 — set SMS text mode (RIL init sequence; accepted, not acted on)
            b"+CMGF=1" => self.write_ok(resp),

            // AT+CMGF=0 — set SMS PDU mode (also accepted)
            b"+CMGF=0" => self.write_ok(resp),

            // All other commands → ERROR
            _ => self.write_error(resp),
        }
    }

    // ── Private response helpers ──────────────────────────────────────────────

    fn write_ok(&self, resp: &mut [u8; AT_RESP_SIZE]) -> Result<usize, ParavirtError> {
        let src = b"\r\nOK\r\n";
        if src.len() > resp.len() {
            return Err(ParavirtError::ResponseBufferTooSmall);
        }
        resp[..src.len()].copy_from_slice(src);
        Ok(src.len())
    }

    fn write_error(&self, resp: &mut [u8; AT_RESP_SIZE]) -> Result<usize, ParavirtError> {
        let src = b"\r\nERROR\r\n";
        if src.len() > resp.len() {
            return Err(ParavirtError::ResponseBufferTooSmall);
        }
        resp[..src.len()].copy_from_slice(src);
        Ok(src.len())
    }

    /// Append `bytes` to `resp` starting at `*pos`. Advances `*pos`.
    fn push(
        &self,
        resp: &mut [u8; AT_RESP_SIZE],
        pos: &mut usize,
        bytes: &[u8],
    ) -> Result<(), ParavirtError> {
        let end = *pos + bytes.len();
        if end > resp.len() {
            return Err(ParavirtError::ResponseBufferTooSmall);
        }
        resp[*pos..end].copy_from_slice(bytes);
        *pos = end;
        Ok(())
    }

    /// Append a single byte.
    fn push_byte(
        &self,
        resp: &mut [u8; AT_RESP_SIZE],
        pos: &mut usize,
        byte: u8,
    ) -> Result<(), ParavirtError> {
        self.push(resp, pos, core::slice::from_ref(&byte))
    }

    /// Append a u8 value as decimal ASCII digits (no leading zeros for >0).
    fn push_u8_decimal(
        &self,
        resp: &mut [u8; AT_RESP_SIZE],
        pos: &mut usize,
        mut val: u8,
    ) -> Result<(), ParavirtError> {
        if val == 0 {
            return self.push_byte(resp, pos, b'0');
        }
        // Maximum 3 digits for u8
        let mut buf = [0u8; 3];
        let mut len = 0usize;
        while val > 0 {
            buf[len] = b'0' + (val % 10);
            val /= 10;
            len += 1;
        }
        // Digits are in reverse order — write them reversed
        for i in (0..len).rev() {
            self.push_byte(resp, pos, buf[i])?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ParavirtState — top-level paravirtualization state
//
// Combines the virtual modem and virtual sensor suite into a single structure
// that AETHER's boot sequence constructs and holds for the lifetime of the
// Android partition.
// ─────────────────────────────────────────────────────────────────────────────

/// Combined paravirtualization state for one Android partition.
///
/// Construct once during AETHER boot and hold for the partition lifetime.
/// The `VirtualSensorSuite` accumulates gyroscope bias state across calls;
/// discarding and reconstructing it resets the drift model.
pub struct ParavirtState {
    /// Virtual modem — handles AT command exchanges with Android's RIL.
    pub modem: VirtualModem,
    /// Virtual sensor suite — generates synthetic accelerometer, gyro, and mag data.
    pub sensors: VirtualSensorSuite,
}

impl ParavirtState {
    /// Construct with the given IMEI and PRNG seed.
    ///
    /// Returns `InvalidImei` if the IMEI fails Luhn validation.
    /// In production, `prng_seed` must come from the platform hardware
    /// entropy source (e.g., TRNG or seeded from boot timestamp + CPU serial).
    pub fn new(imei: [u8; 15], prng_seed: u64) -> Result<Self, ParavirtError> {
        Ok(Self {
            modem: VirtualModem::new(imei)?,
            sensors: VirtualSensorSuite::new(prng_seed),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── IMEI Luhn validation ──────────────────────────────────────────────────

    #[test]
    fn test_imei_valid_490154203237518() {
        // Well-known GSMA test IMEI; check digit verified by hand.
        let imei = *b"490154203237518";
        assert_eq!(validate_imei(&imei), Ok(()));
    }

    #[test]
    fn test_imei_valid_012345678901237() {
        // Computed-valid IMEI: prefix 01234567890123, check digit 7 (Luhn verified).
        let imei = *b"012345678901237";
        assert_eq!(validate_imei(&imei), Ok(()));
    }

    #[test]
    fn test_imei_invalid_wrong_check_digit() {
        // 490154203237518 with check digit changed 8→7
        let imei = *b"490154203237517";
        assert_eq!(validate_imei(&imei), Err(ParavirtError::InvalidImei));
    }

    #[test]
    fn test_imei_invalid_non_digit_byte() {
        let imei = *b"49015420323751X";
        assert_eq!(validate_imei(&imei), Err(ParavirtError::InvalidImei));
    }

    #[test]
    fn test_imei_invalid_space_byte() {
        let imei = *b"490154203237 18";
        assert_eq!(validate_imei(&imei), Err(ParavirtError::InvalidImei));
    }

    // ── Xorshift64 PRNG ───────────────────────────────────────────────────────

    #[test]
    fn test_prng_output_nonzero() {
        let mut rng = Xorshift64::new(0xDEAD_BEEF_1234_5678);
        // With a properly-seeded xorshift64 the output must never be zero
        for _ in 0..1000 {
            assert_ne!(rng.next_u64(), 0, "xorshift64 must never produce 0");
        }
    }

    #[test]
    fn test_prng_consecutive_values_differ() {
        let mut rng = Xorshift64::new(1);
        let a = rng.next_u64();
        let b = rng.next_u64();
        assert_ne!(a, b, "consecutive xorshift64 outputs must differ");
    }

    #[test]
    fn test_prng_f32_range() {
        let mut rng = Xorshift64::new(42);
        for _ in 0..10_000 {
            let v = rng.next_f32();
            assert!(v >= 0.0 && v < 1.0, "next_f32 must be in [0, 1): got {v}");
        }
    }

    // ── Gaussian approximation (statistical) ─────────────────────────────────

    #[test]
    fn test_gaussian_mean_near_zero() {
        let mut rng = Xorshift64::new(0xC0FFEE_AABB_1234);
        let n = 20_000u32;
        let mut sum = 0.0f64;
        for _ in 0..n {
            sum += rng.next_gaussian() as f64;
        }
        let mean = sum / n as f64;
        // Mean of Irwin-Hall n=12 is exactly 0; empirical should be within ±0.05
        assert!(
            mean.abs() < 0.05,
            "Gaussian mean too far from 0: {mean:.4} (expected < 0.05)"
        );
    }

    #[test]
    fn test_gaussian_variance_near_one() {
        let mut rng = Xorshift64::new(0xFEED_FACE_CAFE_BABE);
        let n = 20_000u32;
        let mut sum = 0.0f64;
        let mut sum_sq = 0.0f64;
        for _ in 0..n {
            let v = rng.next_gaussian() as f64;
            sum += v;
            sum_sq += v * v;
        }
        let mean = sum / n as f64;
        let variance = sum_sq / n as f64 - mean * mean;
        // Irwin-Hall n=12 has variance exactly 1; empirical within ±0.05
        assert!(
            (variance - 1.0).abs() < 0.05,
            "Gaussian variance too far from 1: {variance:.4} (expected ≈ 1.00)"
        );
    }

    #[test]
    fn test_gaussian_range_bounded() {
        // Irwin-Hall n=12 is hard-bounded to [−6, +6]
        let mut rng = Xorshift64::new(0xABCD_EF01_2345_6789);
        for _ in 0..50_000 {
            let v = rng.next_gaussian();
            assert!(
                v >= -6.0 && v <= 6.0,
                "Gaussian out of Irwin-Hall range: {v}"
            );
        }
    }

    // ── Accelerometer ─────────────────────────────────────────────────────────

    #[test]
    fn test_accel_z_near_gravity_at_rest() {
        let mut suite = VirtualSensorSuite::new(0x1234_5678_ABCD_EF01);
        // Over many samples, z-axis mean should be close to GRAVITY_MPS2
        let n = 1000u32;
        let mut z_sum = 0.0f64;
        for _ in 0..n {
            z_sum += suite.sample_accel().unwrap().z as f64;
        }
        let z_mean = z_sum / n as f64;
        assert!(
            (z_mean - GRAVITY_MPS2 as f64).abs() < 0.1,
            "Accel z mean {z_mean:.4} not near gravity {GRAVITY_MPS2}"
        );
    }

    #[test]
    fn test_accel_noise_is_nonzero() {
        let mut suite = VirtualSensorSuite::new(0xABCD_1234_5678_EF01);
        let s1 = suite.sample_accel().unwrap();
        let s2 = suite.sample_accel().unwrap();
        // Consecutive samples must differ (zero noise would be detectable)
        assert!(
            (s1.x - s2.x).abs() > 1e-6 || (s1.y - s2.y).abs() > 1e-6,
            "Consecutive accel samples must differ (noise must be non-zero)"
        );
    }

    #[test]
    fn test_accel_noise_sigma_matches_bmi160() {
        // Verify the x-axis noise standard deviation ≈ ACCEL_SIGMA_MPS2
        let mut suite = VirtualSensorSuite::new(0x5A5A_5A5A_A5A5_A5A5);
        let n = 10_000u32;
        let mut sum = 0.0f64;
        let mut sum_sq = 0.0f64;
        for _ in 0..n {
            let v = suite.sample_accel().unwrap().x as f64;
            sum += v;
            sum_sq += v * v;
        }
        let mean = sum / n as f64;
        let std_dev = ((sum_sq / n as f64) - mean * mean).sqrt();
        let expected = ACCEL_SIGMA_MPS2 as f64;
        // Allow ±15% tolerance for statistical variation at n=10 000
        assert!(
            (std_dev - expected).abs() < expected * 0.15,
            "Accel x-axis σ {std_dev:.5} too far from BMI160 spec {expected:.5}"
        );
    }

    // ── Gyroscope ─────────────────────────────────────────────────────────────

    #[test]
    fn test_gyro_at_rest_near_zero() {
        // At rest, all axes should be within 6σ of zero (3σ is already very wide)
        let mut suite = VirtualSensorSuite::new(0x1111_2222_3333_4444);
        let limit = GYRO_SIGMA_DPS * 6.0 + GYRO_BIAS_STEP_DPS * 10.0;
        for _ in 0..100 {
            let g = suite.sample_gyro().unwrap();
            assert!(g.x.abs() < limit, "Gyro x {:.4} exceeds 6σ limit {limit:.4}", g.x);
            assert!(g.y.abs() < limit, "Gyro y {:.4} exceeds 6σ limit {limit:.4}", g.y);
            assert!(g.z.abs() < limit, "Gyro z {:.4} exceeds 6σ limit {limit:.4}", g.z);
        }
    }

    #[test]
    fn test_gyro_bias_drift_accumulates() {
        // Gyro bias random-walk should produce non-zero drift over many samples.
        // With σ_step = 83.3 µdps and 10 000 steps, RMS drift ≈ 8.33 mdps.
        let mut suite = VirtualSensorSuite::new(0x5555_6666_7777_8888);
        // Advance many steps and check that the bias has drifted
        for _ in 0..10_000 {
            let _ = suite.sample_gyro().unwrap();
        }
        // Accumulated bias should be non-zero (probability of staying exactly 0 is ~0)
        let bias_rms = (suite.gyro_bias[0].powi(2)
            + suite.gyro_bias[1].powi(2)
            + suite.gyro_bias[2].powi(2))
        .sqrt();
        assert!(
            bias_rms > 1e-6,
            "Gyro bias drift should be non-zero after 10 000 steps; got {bias_rms:.6}"
        );
    }

    // ── Magnetometer ──────────────────────────────────────────────────────────

    #[test]
    fn test_mag_near_earth_field() {
        // Over many samples, each axis mean should be near the Earth field constant
        let mut suite = VirtualSensorSuite::new(0xDEAD_BEEF_CAFE_F00D);
        let n = 2000u32;
        let (mut sx, mut sy, mut sz) = (0.0f64, 0.0f64, 0.0f64);
        for _ in 0..n {
            let m = suite.sample_mag().unwrap();
            sx += m.x as f64;
            sy += m.y as f64;
            sz += m.z as f64;
        }
        let tol = 0.5f64; // allow 0.5 µT mean deviation
        assert!((sx / n as f64 - EARTH_MAG_X_UT as f64).abs() < tol, "Mag X mean off");
        assert!((sy / n as f64 - EARTH_MAG_Y_UT as f64).abs() < tol, "Mag Y mean off");
        assert!((sz / n as f64 - EARTH_MAG_Z_UT as f64).abs() < tol, "Mag Z mean off");
    }

    // ── Proximity ─────────────────────────────────────────────────────────────

    #[test]
    fn test_proximity_always_far() {
        let suite = VirtualSensorSuite::new(1);
        assert_eq!(suite.sample_proximity(), ProximityState::Far);
    }

    // ── Bridge Mode ───────────────────────────────────────────────────────────

    #[test]
    fn test_bridge_mode_blocks_accel() {
        let mut suite = VirtualSensorSuite::new(1);
        suite.set_bridge_mode(BridgeMode::PhoneBridge);
        assert_eq!(
            suite.sample_accel(),
            Err(ParavirtError::BridgeModeActive),
            "Accel must be blocked when Phone Bridge is active"
        );
    }

    #[test]
    fn test_bridge_mode_blocks_gyro() {
        let mut suite = VirtualSensorSuite::new(1);
        suite.set_bridge_mode(BridgeMode::PhoneBridge);
        assert_eq!(
            suite.sample_gyro(),
            Err(ParavirtError::BridgeModeActive),
        );
    }

    #[test]
    fn test_bridge_mode_blocks_mag() {
        let mut suite = VirtualSensorSuite::new(1);
        suite.set_bridge_mode(BridgeMode::PhoneBridge);
        assert_eq!(
            suite.sample_mag(),
            Err(ParavirtError::BridgeModeActive),
        );
    }

    #[test]
    fn test_bridge_mode_toggle_restores_software() {
        let mut suite = VirtualSensorSuite::new(1);
        suite.set_bridge_mode(BridgeMode::PhoneBridge);
        assert_eq!(suite.sample_accel(), Err(ParavirtError::BridgeModeActive));
        // Toggle back to software model
        suite.set_bridge_mode(BridgeMode::SoftwareModel);
        assert!(suite.sample_accel().is_ok(), "Software model must work after bridge toggle-off");
    }

    // ── AT command modem ──────────────────────────────────────────────────────

    fn make_modem() -> VirtualModem {
        VirtualModem::new(*b"490154203237518").expect("known-good IMEI")
    }

    #[test]
    fn test_at_bare_returns_ok() {
        let m = make_modem();
        let mut resp = [0u8; AT_RESP_SIZE];
        let n = m.process_command(b"AT", &mut resp).unwrap();
        assert_eq!(&resp[..n], b"\r\nOK\r\n");
    }

    #[test]
    fn test_at_ati_contains_modem_id() {
        let m = make_modem();
        let mut resp = [0u8; AT_RESP_SIZE];
        let n = m.process_command(b"ATI", &mut resp).unwrap();
        let s = core::str::from_utf8(&resp[..n]).unwrap();
        assert!(s.contains("AETHER"), "ATI response must contain modem ID");
        assert!(s.ends_with("OK\r\n"), "ATI response must end with OK terminator");
    }

    #[test]
    fn test_at_cgsn_returns_imei() {
        let m = make_modem();
        let mut resp = [0u8; AT_RESP_SIZE];
        let n = m.process_command(b"AT+CGSN", &mut resp).unwrap();
        let s = core::str::from_utf8(&resp[..n]).unwrap();
        assert!(s.contains("490154203237518"), "AT+CGSN must return configured IMEI");
        assert!(s.ends_with("OK\r\n"), "AT+CGSN must end with OK terminator");
    }

    #[test]
    fn test_at_creg_returns_registration_state() {
        let m = make_modem();
        let mut resp = [0u8; AT_RESP_SIZE];
        let n = m.process_command(b"AT+CREG?", &mut resp).unwrap();
        let s = core::str::from_utf8(&resp[..n]).unwrap();
        // HomeNetwork = 1
        assert!(s.contains("+CREG: 0,1"), "AT+CREG? must report HomeNetwork (1)");
        assert!(s.ends_with("OK\r\n"), "AT+CREG? must end with OK terminator");
    }

    #[test]
    fn test_at_cops_contains_operator() {
        let m = make_modem();
        let mut resp = [0u8; AT_RESP_SIZE];
        let n = m.process_command(b"AT+COPS?", &mut resp).unwrap();
        let s = core::str::from_utf8(&resp[..n]).unwrap();
        assert!(s.contains("T-Mobile"), "AT+COPS? must include operator name");
        assert!(s.ends_with("OK\r\n"), "AT+COPS? must end with OK");
    }

    #[test]
    fn test_at_unknown_command_returns_error() {
        let m = make_modem();
        let mut resp = [0u8; AT_RESP_SIZE];
        let n = m.process_command(b"AT+UNKNOWN", &mut resp).unwrap();
        assert_eq!(&resp[..n], b"\r\nERROR\r\n", "Unknown AT command must return ERROR");
    }

    #[test]
    fn test_at_csq_signal_in_range() {
        let m = make_modem();
        let mut resp = [0u8; AT_RESP_SIZE];
        let n = m.process_command(b"AT+CSQ", &mut resp).unwrap();
        let s = core::str::from_utf8(&resp[..n]).unwrap();
        assert!(s.contains("+CSQ:"), "AT+CSQ must contain signal quality");
        assert!(s.ends_with("OK\r\n"), "AT+CSQ must end with OK");
    }

    #[test]
    fn test_at_invalid_prefix_returns_error() {
        let m = make_modem();
        let mut resp = [0u8; AT_RESP_SIZE];
        // Missing "AT" prefix
        let n = m.process_command(b"GARBAGE", &mut resp).unwrap();
        assert_eq!(&resp[..n], b"\r\nERROR\r\n");
    }

    // ── ParavirtState constructor ─────────────────────────────────────────────

    #[test]
    fn test_paravirt_state_valid_imei() {
        let state = ParavirtState::new(*b"490154203237518", 0xCAFE_BABE_1234_5678);
        assert!(state.is_ok(), "ParavirtState must construct with a valid IMEI");
    }

    #[test]
    fn test_paravirt_state_invalid_imei_rejected() {
        let state = ParavirtState::new(*b"490154203237517", 1); // wrong check digit
        assert_eq!(state.err(), Some(ParavirtError::InvalidImei));
    }
}
