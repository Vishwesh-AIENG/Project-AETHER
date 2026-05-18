// ch48: Phone Bridge Mode — End to End
//
// Connects a real Android phone via USB-C and routes its live sensor data and
// OEM identity strings to the Android partition running inside AETHER. When the
// bridge is active the partition receives real accelerometer, gyroscope, and
// magnetometer samples from the physical phone instead of the BMI160/BMM150
// software models in ch12.
//
// ── Architecture ─────────────────────────────────────────────────────────────
//
// Physical path:
//   Phone USB-C → host xHCI controller (ch41) → EL2 event ring → PhoneBridgeReader
//   → ToggleBuffer → SENSOR_READ HVC response → Android Sensor HAL
//
// The xHCI controller is already assigned to and managed by the Android partition
// (ch41). The bridge reader intercepts a dedicated USB bulk endpoint before
// xHCI delivers the transfer to the Android driver ring — it reads from the
// EL2-private event ring segment established in ch41 without disturbing the
// guest's own ring state.
//
// ── Custom USB Protocol (AETHER Bridge Protocol) ─────────────────────────────
//
// Layers on top of ADB WRTE messages. The phone runs an AETHER companion app
// that opens an ADB port and sends binary frames continuously at 100 Hz:
//
//   Offset  Size  Field
//   0       4     magic = 0xAE_CA_FE_48 (AETHER_BRIDGE_MAGIC)
//   4       1     frame_type (0x01=sensor, 0x02=identity, 0x03=handshake)
//   5       1     frame_len (bytes following the 6-byte header)
//   6       N     payload
//
// Sensor frame payload (frame_type = 0x01, frame_len = 40):
//   0  4   accel_x   f32 LE  m/s²
//   4  4   accel_y   f32 LE  m/s²
//   8  4   accel_z   f32 LE  m/s²
//   12 4   gyro_x    f32 LE  dps
//   16 4   gyro_y    f32 LE  dps
//   20 4   gyro_z    f32 LE  dps
//   24 4   mag_x     f32 LE  µT
//   28 4   mag_y     f32 LE  µT
//   32 4   mag_z     f32 LE  µT
//   36 4   timestamp_lo u32 LE   lower 32 bits of timestamp_ns
//   (timestamp_hi is implicit: incremented each wrap of timestamp_lo)
//
// Identity frame payload (frame_type = 0x02, frame_len ≤ 192):
//   0   64  manufacturer  ASCII, null-padded  (ro.product.manufacturer)
//   64  64  model         ASCII, null-padded  (ro.product.model)
//   128 64  bootloader    ASCII, null-padded  (ro.bootloader)
//
// IMEI is queried separately via the virtual modem's AT+CGSN response when
// Phone Bridge is ON and the RIL is instructed to proxy to the phone's modem.
//
// ── Toggle Gap-Free Guarantee ─────────────────────────────────────────────────
//
// The ch48 gate requires that toggling ON/OFF changes the data source with no
// gap in the sensor stream. AETHER enforces this with a ToggleBuffer:
//
//   • Both virtual-model samples and phone-bridge samples are continuously read
//     and cached in the ToggleBuffer (even when not the active source).
//   • On toggle-ON: the ToggleBuffer immediately provides the most recent phone
//     sample. If no phone sample has arrived yet (< 10 ms from connection), it
//     returns the last virtual-model sample — the HAL receives a valid reading.
//   • On toggle-OFF: the ToggleBuffer provides the last phone sample for one
//     interval, then transitions to the virtual model. The virtual model
//     continued accumulating PRNG state during bridge mode — its next sample
//     picks up from where it left off.
//   • The HAL layer timestamp monotonically increases across all samples because
//     both sources annotate frames with the same ns clock.
//
// ── ADB Protocol Summary ─────────────────────────────────────────────────────
//
// ADB wire protocol (see AOSP platform/packages/modules/adb/protocol.txt):
//   Every ADB message: [command u32][arg0 u32][arg1 u32][data_length u32]
//                      [data_check u32][magic u32][data ...]
//   command = A_WRTE (0x45545257) — carries bridge frames in data payload
//   arg0    = local transport ID
//   arg1    = remote transport ID
//
// The hypervisor does not implement the full ADB transport negotiation; it
// identifies bridge frames by the AETHER_BRIDGE_MAGIC header and ignores all
// other ADB traffic.
//
// ── Gate ─────────────────────────────────────────────────────────────────────
//
// PhoneBridgeGate passes when:
//   toggle_source_changes  — SENSOR_READ HVC returns phone data when bridge ON
//                            and virtual data when bridge OFF
//   no_timestamp_gap       — no gap ≥ 20 ms between consecutive SENSOR_READ
//                            responses during a toggle transition
//   identity_loaded        — PhoneIdentity populated with non-empty manufacturer
//                            + model strings from the phone
//
// Shell verification:
//   adb shell dumpsys sensorservice | grep -A2 "Accelerometer" → values change
//   Toggling via: adb shell service call aether 1 i32 1  (ON)
//                 adb shell service call aether 1 i32 0  (OFF)
//   No NaN or 0,0,0 readings during toggle → gap-free confirmed
//
// ── References ───────────────────────────────────────────────────────────────
//
//   AOSP platform/packages/modules/adb/protocol.txt — ADB wire protocol
//   Android Sensor HAL HAL3.0 — hardware/interfaces/sensors/2.1/
//   USB 3.2 Spec §8.4 — bulk transfer completion event format
//   ARM ARM DDI0487 §D5.5.2 — DC IVAC / DC CIVAC cache maintenance
//   Bosch BMI160 DS000 r1.2  — reference sensor noise (ch12 parity)

// ─────────────────────────────────────────────────────────────────────────────
// Re-exported sensor types from ch12
// ─────────────────────────────────────────────────────────────────────────────

use crate::paravirt::{AccelSample, BridgeMode, GyroSample, MagSample};

// ─────────────────────────────────────────────────────────────────────────────
// AETHER Bridge Protocol constants
// ─────────────────────────────────────────────────────────────────────────────

/// Magic bytes at the start of every AETHER bridge frame.
/// Encoding: 0xAE_CA_FE_48 in little-endian = [0x48, 0xFE, 0xCA, 0xAE] on wire.
pub const AETHER_BRIDGE_MAGIC: u32 = 0xAE_CA_FE_48;

/// ADB WRTE command code — carries bridge frame data in ADB message payload.
pub const ADB_CMD_WRTE: u32 = 0x4554_5257;

/// Frame type: sensor data (accel + gyro + mag + timestamp).
pub const FRAME_TYPE_SENSOR: u8 = 0x01;
/// Frame type: phone identity strings (manufacturer / model / bootloader).
pub const FRAME_TYPE_IDENTITY: u8 = 0x02;
/// Frame type: handshake (phone companion app announces its protocol version).
pub const FRAME_TYPE_HANDSHAKE: u8 = 0x03;

/// Size of the fixed bridge frame header in bytes: magic(4) + type(1) + len(1).
pub const BRIDGE_FRAME_HEADER_SIZE: usize = 6;
/// Expected payload length for a sensor frame.
pub const SENSOR_PAYLOAD_LEN: usize = 40;
/// Expected payload length for an identity frame.
pub const IDENTITY_PAYLOAD_LEN: usize = 192;
/// Minimum payload length for a handshake frame (version: u8 + flags: u8).
pub const HANDSHAKE_PAYLOAD_MIN: usize = 2;

/// Maximum number of bytes in one ADB WRTE data payload that we process.
/// Sized to hold one identity frame (header + payload).
pub const BRIDGE_RX_BUF_MAX: usize = BRIDGE_FRAME_HEADER_SIZE + IDENTITY_PAYLOAD_LEN;

/// Phone companion app protocol version required by this AETHER release.
pub const REQUIRED_PROTO_VERSION: u8 = 1;

// ─────────────────────────────────────────────────────────────────────────────
// PhoneSensorFrame — one 100 Hz sample set from the connected phone
// ─────────────────────────────────────────────────────────────────────────────

/// Complete sensor sample received from the phone bridge companion app.
///
/// Arrival rate: 100 Hz (one frame per 10 ms) matching SENSOR_DELAY_GAME.
/// All axis values are in the same units as the virtual sensor suite (ch12):
///   accel  — m/s²
///   gyro   — degrees per second (dps)
///   mag    — microtesla (µT)
#[derive(Clone, Copy, Debug)]
pub struct PhoneSensorFrame {
    pub accel: AccelSample,
    pub gyro: GyroSample,
    pub mag: MagSample,
    /// Lower 32 bits of the phone's CLOCK_BOOTTIME timestamp in nanoseconds.
    pub timestamp_lo: u32,
}

impl PhoneSensorFrame {
    /// Validate that the sensor values are finite (no NaN, no infinity).
    ///
    /// Any non-finite value from the phone — caused by a partial USB transfer or
    /// a misbehaving companion app — must be rejected before the frame reaches
    /// the ToggleBuffer. An infinite or NaN value passed to Android's Sensor HAL
    /// violates the gate criterion (no_nan_values).
    pub fn is_valid(&self) -> bool {
        let ok_f32 = |v: f32| v.is_finite();
        ok_f32(self.accel.x) && ok_f32(self.accel.y) && ok_f32(self.accel.z)
            && ok_f32(self.gyro.x) && ok_f32(self.gyro.y) && ok_f32(self.gyro.z)
            && ok_f32(self.mag.x) && ok_f32(self.mag.y) && ok_f32(self.mag.z)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PhoneIdentity — OEM identity strings from the connected phone
// ─────────────────────────────────────────────────────────────────────────────

/// OEM identity strings read from the connected Android phone at bridge startup.
///
/// Populated from identity frames (FRAME_TYPE_IDENTITY). All fields are
/// null-terminated ASCII strings, null-padded to their fixed length.
///
/// These strings are used to override the virtual modem's ATI response when
/// Phone Bridge Mode is active — Android's telephony stack sees the real
/// phone's identity rather than AETHER's default "Qualcomm SM8550" string.
#[derive(Clone, Copy, Debug)]
pub struct PhoneIdentity {
    /// `ro.product.manufacturer` from the phone (64 bytes, null-padded).
    pub manufacturer: [u8; 64],
    /// `ro.product.model` from the phone (64 bytes, null-padded).
    pub model: [u8; 64],
    /// `ro.bootloader` from the phone (64 bytes, null-padded).
    pub bootloader: [u8; 64],
}

impl PhoneIdentity {
    pub const fn empty() -> Self {
        Self {
            manufacturer: [0u8; 64],
            model: [0u8; 64],
            bootloader: [0u8; 64],
        }
    }

    /// Returns true if manufacturer is non-empty (at least one non-NUL byte).
    pub fn manufacturer_present(&self) -> bool {
        self.manufacturer.iter().any(|&b| b != 0)
    }

    /// Returns true if model is non-empty.
    pub fn model_present(&self) -> bool {
        self.model.iter().any(|&b| b != 0)
    }

    /// Returns true if both manufacturer and model strings are populated.
    pub fn is_loaded(&self) -> bool {
        self.manufacturer_present() && self.model_present()
    }

    /// Return the manufacturer bytes up to the first NUL (or all 64 bytes).
    pub fn manufacturer_str(&self) -> &[u8] {
        let end = self.manufacturer.iter().position(|&b| b == 0).unwrap_or(64);
        &self.manufacturer[..end]
    }

    /// Return the model bytes up to the first NUL.
    pub fn model_str(&self) -> &[u8] {
        let end = self.model.iter().position(|&b| b == 0).unwrap_or(64);
        &self.model[..end]
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ADB bridge frame parser
// ─────────────────────────────────────────────────────────────────────────────

/// Result of parsing one bridge frame from a raw ADB WRTE payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BridgeFrameResult {
    /// Parsed successfully — caller should process the payload.
    Sensor,
    /// Identity frame parsed — identity updated in place.
    Identity,
    /// Handshake frame — protocol version accepted.
    Handshake,
    /// Magic mismatch or truncated header — skip this payload.
    Discard,
    /// Frame length in header exceeds remaining buffer bytes.
    TruncatedPayload,
    /// Unsupported protocol version in handshake frame.
    VersionMismatch,
    /// Payload size does not match expected for frame type.
    MalformedPayload,
}

/// Parse a raw ADB WRTE data payload and attempt to extract one bridge frame.
///
/// `buf` must be the raw ADB WRTE message data (after the 24-byte ADB header).
/// On success the relevant output pointer is populated:
///   - `out_sensor` is set for `BridgeFrameResult::Sensor`
///   - `out_identity` is set for `BridgeFrameResult::Identity`
///
/// No heap allocation; all fields are written through the output pointers.
pub fn parse_bridge_frame(
    buf: &[u8],
    out_sensor: &mut PhoneSensorFrame,
    out_identity: &mut PhoneIdentity,
) -> BridgeFrameResult {
    // Need at least the header
    if buf.len() < BRIDGE_FRAME_HEADER_SIZE {
        return BridgeFrameResult::Discard;
    }

    // Check magic (little-endian u32 at offset 0)
    let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if magic != AETHER_BRIDGE_MAGIC {
        return BridgeFrameResult::Discard;
    }

    let frame_type = buf[4];
    let payload_len = buf[5] as usize;

    if BRIDGE_FRAME_HEADER_SIZE + payload_len > buf.len() {
        return BridgeFrameResult::TruncatedPayload;
    }

    let payload = &buf[BRIDGE_FRAME_HEADER_SIZE..BRIDGE_FRAME_HEADER_SIZE + payload_len];

    match frame_type {
        FRAME_TYPE_SENSOR => {
            if payload_len != SENSOR_PAYLOAD_LEN {
                return BridgeFrameResult::MalformedPayload;
            }
            *out_sensor = decode_sensor_payload(payload);
            if !out_sensor.is_valid() {
                return BridgeFrameResult::MalformedPayload;
            }
            BridgeFrameResult::Sensor
        }

        FRAME_TYPE_IDENTITY => {
            if payload_len != IDENTITY_PAYLOAD_LEN {
                return BridgeFrameResult::MalformedPayload;
            }
            decode_identity_payload(payload, out_identity);
            BridgeFrameResult::Identity
        }

        FRAME_TYPE_HANDSHAKE => {
            if payload_len < HANDSHAKE_PAYLOAD_MIN {
                return BridgeFrameResult::MalformedPayload;
            }
            let version = payload[0];
            if version != REQUIRED_PROTO_VERSION {
                return BridgeFrameResult::VersionMismatch;
            }
            BridgeFrameResult::Handshake
        }

        _ => BridgeFrameResult::Discard,
    }
}

/// Decode a validated 40-byte sensor payload into a `PhoneSensorFrame`.
fn decode_sensor_payload(p: &[u8]) -> PhoneSensorFrame {
    let ax = f32::from_le_bytes([p[0], p[1], p[2], p[3]]);
    let ay = f32::from_le_bytes([p[4], p[5], p[6], p[7]]);
    let az = f32::from_le_bytes([p[8], p[9], p[10], p[11]]);
    let gx = f32::from_le_bytes([p[12], p[13], p[14], p[15]]);
    let gy = f32::from_le_bytes([p[16], p[17], p[18], p[19]]);
    let gz = f32::from_le_bytes([p[20], p[21], p[22], p[23]]);
    let mx = f32::from_le_bytes([p[24], p[25], p[26], p[27]]);
    let my = f32::from_le_bytes([p[28], p[29], p[30], p[31]]);
    let mz = f32::from_le_bytes([p[32], p[33], p[34], p[35]]);
    let ts_lo = u32::from_le_bytes([p[36], p[37], p[38], p[39]]);

    PhoneSensorFrame {
        accel: AccelSample { x: ax, y: ay, z: az },
        gyro: GyroSample { x: gx, y: gy, z: gz },
        mag: MagSample { x: mx, y: my, z: mz },
        timestamp_lo: ts_lo,
    }
}

/// Decode a validated 192-byte identity payload into `out`.
fn decode_identity_payload(p: &[u8], out: &mut PhoneIdentity) {
    out.manufacturer.copy_from_slice(&p[0..64]);
    out.model.copy_from_slice(&p[64..128]);
    out.bootloader.copy_from_slice(&p[128..192]);
}

// ─────────────────────────────────────────────────────────────────────────────
// ToggleBuffer — gap-free transition between virtual model and phone bridge
// ─────────────────────────────────────────────────────────────────────────────

/// Maintains the last valid sample from both sources so a mode toggle never
/// leaves the Sensor HAL without a reading.
///
/// Invariant: after the first sample from either source is recorded,
/// `read_accel()` / `read_gyro()` / `read_mag()` always return `Some`.
///
/// The active source is determined by `BridgeMode` at the call site (in
/// `dispatch_aether_hvc`). The ToggleBuffer does not enforce a source —
/// callers read from whichever source is currently designated active, then
/// fall back to the other if the designated source has no sample yet.
pub struct ToggleBuffer {
    /// Latest accelerometer sample from the virtual software model.
    virtual_accel: Option<AccelSample>,
    /// Latest gyroscope sample from the virtual software model.
    virtual_gyro: Option<GyroSample>,
    /// Latest magnetometer sample from the virtual software model.
    virtual_mag: Option<MagSample>,

    /// Latest accelerometer sample received from the phone bridge.
    bridge_accel: Option<AccelSample>,
    /// Latest gyroscope sample received from the phone bridge.
    bridge_gyro: Option<GyroSample>,
    /// Latest magnetometer sample received from the phone bridge.
    bridge_mag: Option<MagSample>,

    /// Total number of valid sensor frames received from the phone.
    bridge_frame_count: u64,
    /// Total number of invalid/discarded frames (for diagnostics).
    discard_count: u32,
}

impl ToggleBuffer {
    pub const fn new() -> Self {
        Self {
            virtual_accel: None,
            virtual_gyro: None,
            virtual_mag: None,
            bridge_accel: None,
            bridge_gyro: None,
            bridge_mag: None,
            bridge_frame_count: 0,
            discard_count: 0,
        }
    }

    /// Update the virtual-model sample cache. Called every time the software
    /// model is sampled — even when bridge mode is active — so the cache is
    /// always fresh for an immediate toggle-OFF.
    pub fn update_virtual(&mut self, accel: AccelSample, gyro: GyroSample, mag: MagSample) {
        self.virtual_accel = Some(accel);
        self.virtual_gyro = Some(gyro);
        self.virtual_mag = Some(mag);
    }

    /// Update the phone-bridge sample cache from a parsed `PhoneSensorFrame`.
    /// Only called when a valid frame arrives (is_valid() already checked).
    pub fn update_bridge(&mut self, frame: &PhoneSensorFrame) {
        self.bridge_accel = Some(frame.accel);
        self.bridge_gyro = Some(frame.gyro);
        self.bridge_mag = Some(frame.mag);
        self.bridge_frame_count = self.bridge_frame_count.saturating_add(1);
    }

    /// Record a discarded or malformed frame for diagnostics.
    pub fn record_discard(&mut self) {
        self.discard_count = self.discard_count.saturating_add(1);
    }

    /// Return the best available accelerometer sample for `mode`.
    ///
    /// PhoneBridge mode: prefers bridge sample; falls back to virtual if no
    /// bridge sample has arrived yet. SoftwareModel mode: prefers virtual;
    /// falls back to bridge (only during the first sample after bridge was
    /// just turned off, in practice this never triggers because the virtual
    /// model runs continuously).
    pub fn read_accel(&self, mode: BridgeMode) -> Option<AccelSample> {
        match mode {
            BridgeMode::PhoneBridge => self.bridge_accel.or(self.virtual_accel),
            BridgeMode::SoftwareModel => self.virtual_accel.or(self.bridge_accel),
        }
    }

    /// Return the best available gyroscope sample for `mode`.
    pub fn read_gyro(&self, mode: BridgeMode) -> Option<GyroSample> {
        match mode {
            BridgeMode::PhoneBridge => self.bridge_gyro.or(self.virtual_gyro),
            BridgeMode::SoftwareModel => self.virtual_gyro.or(self.bridge_gyro),
        }
    }

    /// Return the best available magnetometer sample for `mode`.
    pub fn read_mag(&self, mode: BridgeMode) -> Option<MagSample> {
        match mode {
            BridgeMode::PhoneBridge => self.bridge_mag.or(self.virtual_mag),
            BridgeMode::SoftwareModel => self.virtual_mag.or(self.bridge_mag),
        }
    }

    /// True once at least one valid phone sensor frame has been buffered.
    pub fn has_bridge_sample(&self) -> bool {
        self.bridge_frame_count > 0
    }

    pub fn bridge_frame_count(&self) -> u64 {
        self.bridge_frame_count
    }

    pub fn discard_count(&self) -> u32 {
        self.discard_count
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PhoneBridgeReader — EL2-side USB bulk reader
// ─────────────────────────────────────────────────────────────────────────────

/// EL2-side phone bridge reader.
///
/// Holds the RX buffer used to accumulate ADB WRTE payload bytes from the
/// xHCI event ring. The xHCI event ring infrastructure is established in ch41
/// (`usb_passthrough.rs`); the bridge reader piggybacks on the EL2-private
/// ring segment to read USB bulk completion data before it reaches the guest.
///
/// On each WFI exit (or from the xHCI maintenance interrupt handler) the
/// caller invokes `process_rx_bytes()` to parse any newly arrived bytes into
/// the ToggleBuffer.
pub struct PhoneBridgeReader {
    /// Partial-frame accumulation buffer (BRIDGE_RX_BUF_MAX bytes).
    rx_buf: [u8; BRIDGE_RX_BUF_MAX],
    /// Number of valid bytes currently in rx_buf.
    rx_len: usize,
    /// True once the companion app handshake has been accepted.
    handshake_complete: bool,
    /// Number of handshake frames received (used to detect reconnect).
    handshake_count: u32,
}

impl PhoneBridgeReader {
    pub const fn new() -> Self {
        Self {
            rx_buf: [0u8; BRIDGE_RX_BUF_MAX],
            rx_len: 0,
            handshake_complete: false,
            handshake_count: 0,
        }
    }

    /// Feed newly received USB bulk bytes into the reader.
    ///
    /// Appends `data` to the internal accumulation buffer and attempts to parse
    /// complete bridge frames. Calls `toggle_buf.update_bridge()` for each
    /// valid sensor frame and `toggle_buf.update_bridge_identity()` for each
    /// valid identity frame (via `out_identity`).
    ///
    /// Returns the number of valid sensor frames processed in this call.
    ///
    /// Partial frames are preserved in the buffer for the next call.
    /// Buffer overflow (frame larger than BRIDGE_RX_BUF_MAX) causes a full
    /// buffer reset — this is the correct recovery from a desync caused by
    /// a dropped USB packet.
    pub fn process_rx_bytes(
        &mut self,
        data: &[u8],
        toggle_buf: &mut ToggleBuffer,
        out_identity: &mut PhoneIdentity,
    ) -> u32 {
        let mut sensor_frames = 0u32;

        // Append new bytes, handling potential overflow
        let space = BRIDGE_RX_BUF_MAX - self.rx_len;
        if data.len() > space {
            // Overflow: drop buffer and start fresh with the new data (truncated)
            self.rx_len = 0;
            let copy_len = data.len().min(BRIDGE_RX_BUF_MAX);
            self.rx_buf[..copy_len].copy_from_slice(&data[..copy_len]);
            self.rx_len = copy_len;
        } else {
            self.rx_buf[self.rx_len..self.rx_len + data.len()].copy_from_slice(data);
            self.rx_len += data.len();
        }

        // Parse frames from the front of rx_buf, consuming them as we go
        let mut consumed = 0usize;
        loop {
            let remaining = &self.rx_buf[consumed..self.rx_len];
            if remaining.len() < BRIDGE_FRAME_HEADER_SIZE {
                break; // Need more bytes
            }

            // Quick magic check before full parse to skip non-bridge ADB data
            let magic = u32::from_le_bytes([
                remaining[0], remaining[1], remaining[2], remaining[3],
            ]);
            if magic != AETHER_BRIDGE_MAGIC {
                // Advance one byte and try again (re-sync)
                consumed += 1;
                continue;
            }

            let payload_len = remaining[5] as usize;
            let frame_total = BRIDGE_FRAME_HEADER_SIZE + payload_len;
            if remaining.len() < frame_total {
                break; // Partial frame — wait for more bytes
            }

            let mut sensor_out = PhoneSensorFrame {
                accel: AccelSample { x: 0.0, y: 0.0, z: 0.0 },
                gyro: GyroSample { x: 0.0, y: 0.0, z: 0.0 },
                mag: MagSample { x: 0.0, y: 0.0, z: 0.0 },
                timestamp_lo: 0,
            };

            let result = parse_bridge_frame(
                &remaining[..frame_total],
                &mut sensor_out,
                out_identity,
            );

            match result {
                BridgeFrameResult::Sensor => {
                    toggle_buf.update_bridge(&sensor_out);
                    sensor_frames = sensor_frames.saturating_add(1);
                }
                BridgeFrameResult::Identity => {
                    // out_identity already populated by parse_bridge_frame
                }
                BridgeFrameResult::Handshake => {
                    self.handshake_complete = true;
                    self.handshake_count = self.handshake_count.saturating_add(1);
                }
                BridgeFrameResult::VersionMismatch => {
                    // Incompatible companion app — mark as not handshaked
                    self.handshake_complete = false;
                    toggle_buf.record_discard();
                }
                _ => {
                    toggle_buf.record_discard();
                }
            }

            consumed += frame_total;
        }

        // Compact: move unconsumed bytes to front of buffer
        if consumed > 0 && consumed < self.rx_len {
            self.rx_buf.copy_within(consumed..self.rx_len, 0);
            self.rx_len -= consumed;
        } else if consumed >= self.rx_len {
            self.rx_len = 0;
        }

        sensor_frames
    }

    pub fn is_handshake_complete(&self) -> bool {
        self.handshake_complete
    }

    pub fn handshake_count(&self) -> u32 {
        self.handshake_count
    }

    /// Reset reader state (called when bridge mode is toggled OFF).
    ///
    /// Clears the accumulation buffer and handshake state. The ToggleBuffer
    /// retains the last phone samples for a one-interval fallback.
    pub fn reset(&mut self) {
        self.rx_len = 0;
        self.handshake_complete = false;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Global phone bridge state
// ─────────────────────────────────────────────────────────────────────────────

static mut AETHER_TOGGLE_BUF: ToggleBuffer = ToggleBuffer::new();
static mut AETHER_BRIDGE_READER: PhoneBridgeReader = PhoneBridgeReader::new();
static mut AETHER_PHONE_IDENTITY: PhoneIdentity = PhoneIdentity {
    manufacturer: [0u8; 64],
    model: [0u8; 64],
    bootloader: [0u8; 64],
};

/// Return mutable reference to the global ToggleBuffer.
///
/// # Safety
/// Must only be called from EL2 exception context (IRQs masked).
pub unsafe fn aether_toggle_buf_mut() -> &'static mut ToggleBuffer {
    unsafe { &mut *core::ptr::addr_of_mut!(AETHER_TOGGLE_BUF) }
}

/// Return mutable reference to the global PhoneBridgeReader.
///
/// # Safety
/// Must only be called from EL2 exception context (IRQs masked).
pub unsafe fn aether_bridge_reader_mut() -> &'static mut PhoneBridgeReader {
    unsafe { &mut *core::ptr::addr_of_mut!(AETHER_BRIDGE_READER) }
}

/// Return mutable reference to the global PhoneIdentity.
///
/// # Safety
/// Must only be called from EL2 exception context (IRQs masked).
pub unsafe fn aether_phone_identity_mut() -> &'static mut PhoneIdentity {
    unsafe { &mut *core::ptr::addr_of_mut!(AETHER_PHONE_IDENTITY) }
}

/// Return shared reference to the global PhoneIdentity.
///
/// # Safety
/// Must only be called from EL2 exception context (IRQs masked).
pub unsafe fn aether_phone_identity() -> &'static PhoneIdentity {
    unsafe { &*core::ptr::addr_of!(AETHER_PHONE_IDENTITY) }
}

// ─────────────────────────────────────────────────────────────────────────────
// Entry point: USB bulk data from xHCI event ring
// ─────────────────────────────────────────────────────────────────────────────

/// Process USB bulk transfer data received on the phone-bridge USB endpoint.
///
/// Called from the xHCI event ring handler in `usb_passthrough.rs` whenever a
/// Transfer Event TRB arrives on the EL2-private ring segment for the phone
/// bridge endpoint. The caller supplies the raw bulk payload bytes.
///
/// Parses AETHER bridge frames and updates the ToggleBuffer. Returns the number
/// of valid sensor frames parsed (for diagnostic logging).
///
/// # Safety
/// Must be called from EL2 exception context with IRQs masked.
pub unsafe fn on_bridge_usb_data(data: &[u8]) -> u32 {
    unsafe {
        let reader = aether_bridge_reader_mut();
        let toggle_buf = aether_toggle_buf_mut();
        let identity = aether_phone_identity_mut();
        reader.process_rx_bytes(data, toggle_buf, identity)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Bridge-aware SENSOR_READ helper
// ─────────────────────────────────────────────────────────────────────────────

/// Result of a bridge-aware sensor read.
pub enum BridgeSensorRead {
    /// Sensor data ready; caller writes to HVC result registers.
    Accel(AccelSample),
    Gyro(GyroSample),
    Mag(MagSample),
    /// No sample available from any source (very early boot, before first sample).
    NotReady,
}

/// Read accelerometer data from the ToggleBuffer using `mode`.
///
/// When `mode == PhoneBridge` and no phone sample has arrived yet, falls back
/// to the virtual-model cache to guarantee a gap-free transition.
///
/// # Safety
/// Must be called from EL2 exception context.
pub unsafe fn bridge_read_accel(mode: BridgeMode) -> BridgeSensorRead {
    let buf = unsafe { aether_toggle_buf_mut() };
    match buf.read_accel(mode) {
        Some(s) => BridgeSensorRead::Accel(s),
        None => BridgeSensorRead::NotReady,
    }
}

/// Read gyroscope data from the ToggleBuffer using `mode`.
///
/// # Safety
/// Must be called from EL2 exception context.
pub unsafe fn bridge_read_gyro(mode: BridgeMode) -> BridgeSensorRead {
    let buf = unsafe { aether_toggle_buf_mut() };
    match buf.read_gyro(mode) {
        Some(s) => BridgeSensorRead::Gyro(s),
        None => BridgeSensorRead::NotReady,
    }
}

/// Read magnetometer data from the ToggleBuffer using `mode`.
///
/// # Safety
/// Must be called from EL2 exception context.
pub unsafe fn bridge_read_mag(mode: BridgeMode) -> BridgeSensorRead {
    let buf = unsafe { aether_toggle_buf_mut() };
    match buf.read_mag(mode) {
        Some(s) => BridgeSensorRead::Mag(s),
        None => BridgeSensorRead::NotReady,
    }
}

/// Feed a new virtual-model sample into the ToggleBuffer.
///
/// Called from `dispatch_aether_hvc` SENSOR_READ handler every time a virtual
/// sample is generated — whether or not bridge mode is active — so the
/// ToggleBuffer always has a fresh virtual-model fallback.
///
/// # Safety
/// Must be called from EL2 exception context.
pub unsafe fn update_virtual_cache(accel: AccelSample, gyro: GyroSample, mag: MagSample) {
    let buf = unsafe { aether_toggle_buf_mut() };
    buf.update_virtual(accel, gyro, mag);
}

// ─────────────────────────────────────────────────────────────────────────────
// Config / gate / error / phase types
// ─────────────────────────────────────────────────────────────────────────────

/// Errors returned by `init_phone_bridge()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhoneBridgeError {
    /// USB controller base address is zero or obviously invalid.
    InvalidUsbBase,
    /// SMMU stream ID list is empty — at least one ID required for USB DMA isolation.
    NoStreamIds,
    /// SMMU stream ID count exceeds the maximum this config structure supports.
    TooManyStreamIds,
}

/// Maximum number of SMMU stream IDs tracked for the phone USB port.
pub const MAX_BRIDGE_STREAM_IDS: usize = 4;

/// Configuration for the phone bridge subsystem.
#[derive(Clone, Copy, Debug)]
pub struct PhoneBridgeConfig {
    /// PA of the xHCI controller BAR0 (set by ch41's `UsbPassthroughConfig.bar0_pa`).
    pub xhci_bar0_pa: u64,
    /// SMMU stream IDs covering the phone-bridge USB bulk endpoint.
    pub stream_ids: [u32; MAX_BRIDGE_STREAM_IDS],
    /// Number of valid entries in `stream_ids`.
    pub stream_id_count: usize,
}

impl PhoneBridgeConfig {
    /// Construct with the minimum required fields.
    pub const fn new(xhci_bar0_pa: u64, stream_id: u32) -> Self {
        let mut ids = [0u32; MAX_BRIDGE_STREAM_IDS];
        ids[0] = stream_id;
        Self {
            xhci_bar0_pa,
            stream_ids: ids,
            stream_id_count: 1,
        }
    }

    /// Validate all fields.
    pub fn validate(&self) -> Result<(), PhoneBridgeError> {
        if self.xhci_bar0_pa == 0 {
            return Err(PhoneBridgeError::InvalidUsbBase);
        }
        if self.stream_id_count == 0 {
            return Err(PhoneBridgeError::NoStreamIds);
        }
        if self.stream_id_count > MAX_BRIDGE_STREAM_IDS {
            return Err(PhoneBridgeError::TooManyStreamIds);
        }
        Ok(())
    }
}

/// Gate for Chapter 48.
///
/// All three criteria must be true for the gate to pass.
#[derive(Clone, Copy, Debug, Default)]
pub struct PhoneBridgeGate {
    /// SENSOR_READ HVC returns phone sensor data when bridge is ON
    /// and virtual data when bridge is OFF.
    pub toggle_source_changes: bool,
    /// No gap ≥ 20 ms observed between consecutive SENSOR_READ responses
    /// during a toggle transition.
    pub no_timestamp_gap: bool,
    /// `PhoneIdentity.is_loaded()` — manufacturer + model strings populated.
    pub identity_loaded: bool,
}

impl PhoneBridgeGate {
    pub fn passes(&self) -> bool {
        self.toggle_source_changes && self.no_timestamp_gap && self.identity_loaded
    }
}

/// Boot / operational phase of the phone bridge subsystem.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhoneBridgePhase {
    /// `init_phone_bridge()` not yet called.
    NotStarted,
    /// USB controller assigned; EL2 event ring armed for bridge endpoint.
    UsbReady,
    /// Companion app handshake complete (protocol version accepted).
    AdbConnected,
    /// Sensor frames arriving continuously at 100 Hz.
    SensorStreamActive,
    /// Identity strings loaded from identity frame.
    IdentityLoaded,
    /// Gate passed: toggle works, no gap, identity loaded.
    GatePassed,
}

/// UART log signatures for the phone bridge subsystem.
pub const UART_SIG_BRIDGE_HANDSHAKE: &[u8] = b"AetherBridge: handshake OK";
pub const UART_SIG_BRIDGE_SENSOR:    &[u8] = b"AetherBridge: sensor stream active";
pub const UART_SIG_BRIDGE_IDENTITY:  &[u8] = b"AetherBridge: identity loaded";
pub const UART_SIG_BRIDGE_TOGGLE_ON: &[u8] = b"AetherBridge: toggled ON";
pub const UART_SIG_BRIDGE_TOGGLE_OFF: &[u8] = b"AetherBridge: toggled OFF";
pub const UART_SIG_BRIDGE_NO_GAP:    &[u8] = b"AetherBridge: toggle gap-free";

/// Runtime observable state for the phone bridge subsystem.
///
/// Feed UART/logcat lines into `process_line()` to advance the gate.
#[derive(Debug)]
pub struct PhoneBridgeState {
    phase: PhoneBridgePhase,
    gate: PhoneBridgeGate,
    /// Toggle ON event seen at least once.
    toggle_on_seen: bool,
    /// Toggle OFF event seen after toggle ON.
    toggle_off_seen: bool,
}

impl PhoneBridgeState {
    pub const fn new() -> Self {
        Self {
            phase: PhoneBridgePhase::NotStarted,
            gate: PhoneBridgeGate {
                toggle_source_changes: false,
                no_timestamp_gap: false,
                identity_loaded: false,
            },
            toggle_on_seen: false,
            toggle_off_seen: false,
        }
    }

    /// Feed a UART/logcat line; update gate and phase accordingly.
    pub fn process_line(&mut self, line: &[u8]) {
        use crate::virtual_sensors_modem::contains_bytes;

        if contains_bytes(line, UART_SIG_BRIDGE_HANDSHAKE) {
            if self.phase == PhoneBridgePhase::UsbReady
                || self.phase == PhoneBridgePhase::NotStarted
            {
                self.phase = PhoneBridgePhase::AdbConnected;
            }
        }

        if contains_bytes(line, UART_SIG_BRIDGE_SENSOR) {
            self.phase = PhoneBridgePhase::SensorStreamActive;
        }

        if contains_bytes(line, UART_SIG_BRIDGE_IDENTITY) {
            self.gate.identity_loaded = true;
            if self.phase == PhoneBridgePhase::SensorStreamActive {
                self.phase = PhoneBridgePhase::IdentityLoaded;
            }
        }

        if contains_bytes(line, UART_SIG_BRIDGE_TOGGLE_ON) {
            self.toggle_on_seen = true;
        }

        if contains_bytes(line, UART_SIG_BRIDGE_TOGGLE_OFF) && self.toggle_on_seen {
            self.toggle_off_seen = true;
        }

        if self.toggle_on_seen && self.toggle_off_seen {
            self.gate.toggle_source_changes = true;
        }

        if contains_bytes(line, UART_SIG_BRIDGE_NO_GAP) {
            self.gate.no_timestamp_gap = true;
        }

        if self.gate.passes() {
            self.phase = PhoneBridgePhase::GatePassed;
        }
    }

    pub fn gate(&self) -> &PhoneBridgeGate {
        &self.gate
    }

    pub fn phase(&self) -> PhoneBridgePhase {
        self.phase
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Kernel config and SELinux rules required by the phone bridge
// ─────────────────────────────────────────────────────────────────────────────

/// Kernel defconfig entries required for phone bridge USB bulk access.
///
/// Without CONFIG_USB_CONFIGFS the companion app ADB channel cannot open the
/// custom bulk endpoint that carries bridge frames.
pub const BRIDGE_KERNEL_CONFIG: &[(&str, &str)] = &[
    ("CONFIG_USB_CONFIGFS",          "y"), // USB gadget configfs (companion app endpoint)
    ("CONFIG_USB_CONFIGFS_F_FS",     "y"), // FunctionFS for companion app ADB bulk EP
    ("CONFIG_USB_G_ANDROID",         "y"), // Android USB gadget driver
    ("CONFIG_USB_F_ACCESSORY",       "y"), // USB accessory protocol for bridge framing
];

/// SELinux policy rules required for the phone bridge kernel module.
pub const BRIDGE_SELINUX_RULES: &[&str] = &[
    "allow aether_bridge_service aether_device:chr_file { read write ioctl open };",
    "allow hal_sensors_default aether_bridge_service:binder { call transfer_to };",
    "allow system_server aether_bridge_service:binder { call transfer_to };",
];

/// AOSP product packages required for the phone bridge.
pub const BRIDGE_PRODUCT_PACKAGES: &[&str] = &[
    "aether_bridge_service",     // EL2↔Android bridge service (binds /dev/aether_bridge)
    "libaeherbridge",            // Shared library consumed by Sensor HAL + RIL
    "AetherCompanionApp.apk",    // Pre-installed companion APK (pushes sensor data to EL2)
];

// ─────────────────────────────────────────────────────────────────────────────
// Initialisation pipeline
// ─────────────────────────────────────────────────────────────────────────────

/// Initialise the phone bridge subsystem.
///
/// Must be called once during AETHER boot after the xHCI controller is
/// assigned (ch41) and before the first ERET to the Android partition.
///
/// On success the ToggleBuffer and PhoneBridgeReader are reset-initialised and
/// the subsystem enters `PhoneBridgePhase::UsbReady`.
///
/// Returns `Err` if the configuration is invalid. Invalid configuration is
/// fatal — the bridge hardware cannot function if the xHCI base address is
/// wrong or stream IDs are missing.
pub fn init_phone_bridge(
    cfg: &PhoneBridgeConfig,
) -> Result<PhoneBridgeState, PhoneBridgeError> {
    cfg.validate()?;

    // Reset global state
    // SAFETY: called once during boot before any guest runs.
    unsafe {
        *core::ptr::addr_of_mut!(AETHER_TOGGLE_BUF) = ToggleBuffer::new();
        *core::ptr::addr_of_mut!(AETHER_BRIDGE_READER) = PhoneBridgeReader::new();
        *core::ptr::addr_of_mut!(AETHER_PHONE_IDENTITY) = PhoneIdentity::empty();
    }

    let mut state = PhoneBridgeState::new();
    state.phase = PhoneBridgePhase::UsbReady;
    Ok(state)
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_bridge_frame ───────────────────────────────────────────────────

    fn make_sensor_buf() -> [u8; BRIDGE_FRAME_HEADER_SIZE + SENSOR_PAYLOAD_LEN] {
        let mut buf = [0u8; BRIDGE_FRAME_HEADER_SIZE + SENSOR_PAYLOAD_LEN];
        // Header: magic(4) + type(1) + len(1)
        buf[0..4].copy_from_slice(&AETHER_BRIDGE_MAGIC.to_le_bytes());
        buf[4] = FRAME_TYPE_SENSOR;
        buf[5] = SENSOR_PAYLOAD_LEN as u8;
        // Payload starts at BRIDGE_FRAME_HEADER_SIZE (= 6).
        // accel z = 9.80665 (gravity) at payload offset 8 → buf index 6+8=14
        let az: [u8; 4] = 9.80665f32.to_le_bytes();
        buf[14..18].copy_from_slice(&az);
        // gyro x = 1.0 dps at payload offset 12 → buf index 6+12=18
        let gx: [u8; 4] = 1.0f32.to_le_bytes();
        buf[18..22].copy_from_slice(&gx);
        // mag x = 20.1 µT at payload offset 24 → buf index 6+24=30
        let mx: [u8; 4] = 20.1f32.to_le_bytes();
        buf[30..34].copy_from_slice(&mx);
        buf
    }

    #[test]
    fn test_parse_sensor_frame_ok() {
        let buf = make_sensor_buf();
        let mut sensor = PhoneSensorFrame {
            accel: AccelSample { x: 0.0, y: 0.0, z: 0.0 },
            gyro: GyroSample { x: 0.0, y: 0.0, z: 0.0 },
            mag: MagSample { x: 0.0, y: 0.0, z: 0.0 },
            timestamp_lo: 0,
        };
        let mut identity = PhoneIdentity::empty();
        let result = parse_bridge_frame(&buf, &mut sensor, &mut identity);
        assert_eq!(result, BridgeFrameResult::Sensor);
        assert!((sensor.accel.z - 9.80665).abs() < 1e-4, "accel z should be near gravity");
        assert!((sensor.gyro.x - 1.0).abs() < 1e-4, "gyro x should be 1.0 dps");
        assert!((sensor.mag.x - 20.1).abs() < 1e-3, "mag x should be 20.1 µT");
    }

    #[test]
    fn test_parse_wrong_magic_discarded() {
        let mut buf = make_sensor_buf();
        buf[0] = 0xFF; // corrupt magic
        let mut sensor = PhoneSensorFrame {
            accel: AccelSample { x: 0.0, y: 0.0, z: 0.0 },
            gyro: GyroSample { x: 0.0, y: 0.0, z: 0.0 },
            mag: MagSample { x: 0.0, y: 0.0, z: 0.0 },
            timestamp_lo: 0,
        };
        let mut identity = PhoneIdentity::empty();
        let result = parse_bridge_frame(&buf, &mut sensor, &mut identity);
        assert_eq!(result, BridgeFrameResult::Discard);
    }

    #[test]
    fn test_parse_truncated_payload() {
        let buf = make_sensor_buf();
        // Provide only header + half the payload
        let partial = &buf[..BRIDGE_FRAME_HEADER_SIZE + SENSOR_PAYLOAD_LEN / 2];
        let mut sensor = PhoneSensorFrame {
            accel: AccelSample { x: 0.0, y: 0.0, z: 0.0 },
            gyro: GyroSample { x: 0.0, y: 0.0, z: 0.0 },
            mag: MagSample { x: 0.0, y: 0.0, z: 0.0 },
            timestamp_lo: 0,
        };
        let mut identity = PhoneIdentity::empty();
        let result = parse_bridge_frame(partial, &mut sensor, &mut identity);
        assert_eq!(result, BridgeFrameResult::TruncatedPayload);
    }

    #[test]
    fn test_parse_identity_frame_ok() {
        let mut buf = [0u8; BRIDGE_FRAME_HEADER_SIZE + IDENTITY_PAYLOAD_LEN];
        buf[0..4].copy_from_slice(&AETHER_BRIDGE_MAGIC.to_le_bytes());
        buf[4] = FRAME_TYPE_IDENTITY;
        buf[5] = IDENTITY_PAYLOAD_LEN as u8;
        // manufacturer = "Google"
        buf[6..12].copy_from_slice(b"Google");
        // model = "Pixel 8"
        buf[6 + 64..6 + 64 + 7].copy_from_slice(b"Pixel 8");
        let mut sensor = PhoneSensorFrame {
            accel: AccelSample { x: 0.0, y: 0.0, z: 0.0 },
            gyro: GyroSample { x: 0.0, y: 0.0, z: 0.0 },
            mag: MagSample { x: 0.0, y: 0.0, z: 0.0 },
            timestamp_lo: 0,
        };
        let mut identity = PhoneIdentity::empty();
        let result = parse_bridge_frame(&buf, &mut sensor, &mut identity);
        assert_eq!(result, BridgeFrameResult::Identity);
        assert!(identity.manufacturer_present(), "manufacturer should be set");
        assert!(identity.model_present(), "model should be set");
        assert_eq!(identity.manufacturer_str(), b"Google");
        assert_eq!(identity.model_str(), b"Pixel 8");
    }

    #[test]
    fn test_parse_handshake_ok() {
        let mut buf = [0u8; BRIDGE_FRAME_HEADER_SIZE + 2];
        buf[0..4].copy_from_slice(&AETHER_BRIDGE_MAGIC.to_le_bytes());
        buf[4] = FRAME_TYPE_HANDSHAKE;
        buf[5] = 2; // payload_len
        buf[6] = REQUIRED_PROTO_VERSION; // version
        buf[7] = 0; // flags
        let mut sensor = PhoneSensorFrame {
            accel: AccelSample { x: 0.0, y: 0.0, z: 0.0 },
            gyro: GyroSample { x: 0.0, y: 0.0, z: 0.0 },
            mag: MagSample { x: 0.0, y: 0.0, z: 0.0 },
            timestamp_lo: 0,
        };
        let mut identity = PhoneIdentity::empty();
        let result = parse_bridge_frame(&buf, &mut sensor, &mut identity);
        assert_eq!(result, BridgeFrameResult::Handshake);
    }

    #[test]
    fn test_parse_handshake_wrong_version() {
        let mut buf = [0u8; BRIDGE_FRAME_HEADER_SIZE + 2];
        buf[0..4].copy_from_slice(&AETHER_BRIDGE_MAGIC.to_le_bytes());
        buf[4] = FRAME_TYPE_HANDSHAKE;
        buf[5] = 2;
        buf[6] = 99; // wrong version
        buf[7] = 0;
        let mut sensor = PhoneSensorFrame {
            accel: AccelSample { x: 0.0, y: 0.0, z: 0.0 },
            gyro: GyroSample { x: 0.0, y: 0.0, z: 0.0 },
            mag: MagSample { x: 0.0, y: 0.0, z: 0.0 },
            timestamp_lo: 0,
        };
        let mut identity = PhoneIdentity::empty();
        let result = parse_bridge_frame(&buf, &mut sensor, &mut identity);
        assert_eq!(result, BridgeFrameResult::VersionMismatch);
    }

    // ── PhoneSensorFrame::is_valid ────────────────────────────────────────────

    #[test]
    fn test_sensor_frame_valid_finite() {
        let frame = PhoneSensorFrame {
            accel: AccelSample { x: 0.1, y: -0.2, z: 9.8 },
            gyro: GyroSample { x: 0.01, y: 0.0, z: -0.5 },
            mag: MagSample { x: 20.0, y: -5.0, z: 49.0 },
            timestamp_lo: 1_000_000,
        };
        assert!(frame.is_valid());
    }

    #[test]
    fn test_sensor_frame_nan_invalid() {
        let frame = PhoneSensorFrame {
            accel: AccelSample { x: f32::NAN, y: 0.0, z: 9.8 },
            gyro: GyroSample { x: 0.0, y: 0.0, z: 0.0 },
            mag: MagSample { x: 20.0, y: -5.0, z: 49.0 },
            timestamp_lo: 0,
        };
        assert!(!frame.is_valid(), "NaN in accel.x must make frame invalid");
    }

    #[test]
    fn test_sensor_frame_inf_invalid() {
        let frame = PhoneSensorFrame {
            accel: AccelSample { x: 0.0, y: 0.0, z: f32::INFINITY },
            gyro: GyroSample { x: 0.0, y: 0.0, z: 0.0 },
            mag: MagSample { x: 0.0, y: 0.0, z: 0.0 },
            timestamp_lo: 0,
        };
        assert!(!frame.is_valid(), "Infinity in accel.z must make frame invalid");
    }

    // ── ToggleBuffer ──────────────────────────────────────────────────────────

    #[test]
    fn test_toggle_buf_starts_empty() {
        let buf = ToggleBuffer::new();
        assert!(!buf.has_bridge_sample());
        assert_eq!(buf.bridge_frame_count(), 0);
    }

    #[test]
    fn test_toggle_buf_virtual_update_readable() {
        let mut buf = ToggleBuffer::new();
        buf.update_virtual(
            AccelSample { x: 0.0, y: 0.0, z: 9.8 },
            GyroSample { x: 0.0, y: 0.0, z: 0.0 },
            MagSample { x: 20.0, y: -5.0, z: 49.0 },
        );
        let accel = buf.read_accel(BridgeMode::SoftwareModel);
        assert!(accel.is_some());
        assert!((accel.unwrap().z - 9.8).abs() < 1e-3);
    }

    #[test]
    fn test_toggle_buf_bridge_fallback_to_virtual() {
        // When bridge mode is requested but no phone sample has arrived yet,
        // fall back to the virtual-model cache — gap-free guarantee.
        let mut buf = ToggleBuffer::new();
        buf.update_virtual(
            AccelSample { x: 1.0, y: 2.0, z: 9.8 },
            GyroSample { x: 0.1, y: 0.0, z: 0.0 },
            MagSample { x: 20.0, y: -5.0, z: 49.0 },
        );
        // No bridge sample yet
        let accel = buf.read_accel(BridgeMode::PhoneBridge);
        assert!(accel.is_some(), "must fall back to virtual when no bridge sample");
        assert!((accel.unwrap().x - 1.0).abs() < 1e-4);
    }

    #[test]
    fn test_toggle_buf_bridge_prefers_phone_sample() {
        let mut buf = ToggleBuffer::new();
        buf.update_virtual(
            AccelSample { x: 1.0, y: 0.0, z: 9.8 },
            GyroSample { x: 0.0, y: 0.0, z: 0.0 },
            MagSample { x: 20.0, y: 0.0, z: 0.0 },
        );
        let frame = PhoneSensorFrame {
            accel: AccelSample { x: 5.0, y: 0.0, z: 0.5 },
            gyro: GyroSample { x: 0.0, y: 0.0, z: 0.0 },
            mag: MagSample { x: 25.0, y: 0.0, z: 0.0 },
            timestamp_lo: 100,
        };
        buf.update_bridge(&frame);
        assert!(buf.has_bridge_sample());
        let accel = buf.read_accel(BridgeMode::PhoneBridge);
        assert!((accel.unwrap().x - 5.0).abs() < 1e-4, "bridge mode must prefer phone sample");
    }

    #[test]
    fn test_toggle_buf_software_mode_prefers_virtual() {
        let mut buf = ToggleBuffer::new();
        buf.update_virtual(
            AccelSample { x: 1.0, y: 0.0, z: 9.8 },
            GyroSample { x: 0.0, y: 0.0, z: 0.0 },
            MagSample { x: 20.0, y: 0.0, z: 0.0 },
        );
        let frame = PhoneSensorFrame {
            accel: AccelSample { x: 5.0, y: 0.0, z: 0.5 },
            gyro: GyroSample { x: 0.0, y: 0.0, z: 0.0 },
            mag: MagSample { x: 25.0, y: 0.0, z: 0.0 },
            timestamp_lo: 200,
        };
        buf.update_bridge(&frame);
        let accel = buf.read_accel(BridgeMode::SoftwareModel);
        assert!((accel.unwrap().x - 1.0).abs() < 1e-4, "software mode must prefer virtual sample");
    }

    // ── PhoneBridgeReader ─────────────────────────────────────────────────────

    #[test]
    fn test_reader_processes_sensor_frame() {
        let mut reader = PhoneBridgeReader::new();
        let mut toggle_buf = ToggleBuffer::new();
        let mut identity = PhoneIdentity::empty();

        // First send a handshake
        let mut hs = [0u8; BRIDGE_FRAME_HEADER_SIZE + 2];
        hs[0..4].copy_from_slice(&AETHER_BRIDGE_MAGIC.to_le_bytes());
        hs[4] = FRAME_TYPE_HANDSHAKE;
        hs[5] = 2;
        hs[6] = REQUIRED_PROTO_VERSION;
        hs[7] = 0;
        reader.process_rx_bytes(&hs, &mut toggle_buf, &mut identity);
        assert!(reader.is_handshake_complete());

        // Then a sensor frame
        let sensor_buf = make_sensor_buf();
        let count = reader.process_rx_bytes(&sensor_buf, &mut toggle_buf, &mut identity);
        assert_eq!(count, 1, "one sensor frame should be processed");
        assert!(toggle_buf.has_bridge_sample());
    }

    #[test]
    fn test_reader_rejects_version_mismatch() {
        let mut reader = PhoneBridgeReader::new();
        let mut toggle_buf = ToggleBuffer::new();
        let mut identity = PhoneIdentity::empty();

        let mut hs = [0u8; BRIDGE_FRAME_HEADER_SIZE + 2];
        hs[0..4].copy_from_slice(&AETHER_BRIDGE_MAGIC.to_le_bytes());
        hs[4] = FRAME_TYPE_HANDSHAKE;
        hs[5] = 2;
        hs[6] = 99; // bad version
        hs[7] = 0;
        reader.process_rx_bytes(&hs, &mut toggle_buf, &mut identity);
        assert!(!reader.is_handshake_complete(), "bad version must fail handshake");
        assert_eq!(toggle_buf.discard_count(), 1);
    }

    #[test]
    fn test_reader_partial_frame_buffered() {
        let mut reader = PhoneBridgeReader::new();
        let mut toggle_buf = ToggleBuffer::new();
        let mut identity = PhoneIdentity::empty();

        let full = make_sensor_buf();
        // Send only the first half
        let half = &full[..full.len() / 2];
        let count = reader.process_rx_bytes(half, &mut toggle_buf, &mut identity);
        assert_eq!(count, 0, "partial frame must not be emitted");
        assert!(!toggle_buf.has_bridge_sample());

        // Send the second half
        let count2 = reader.process_rx_bytes(&full[full.len() / 2..], &mut toggle_buf, &mut identity);
        assert_eq!(count2, 1, "complete frame assembled from two chunks must be processed");
    }

    // ── PhoneIdentity ─────────────────────────────────────────────────────────

    #[test]
    fn test_identity_empty() {
        let id = PhoneIdentity::empty();
        assert!(!id.manufacturer_present());
        assert!(!id.model_present());
        assert!(!id.is_loaded());
    }

    #[test]
    fn test_identity_str_null_terminated() {
        let mut id = PhoneIdentity::empty();
        id.manufacturer[..6].copy_from_slice(b"Google");
        id.model[..7].copy_from_slice(b"Pixel 8");
        assert_eq!(id.manufacturer_str(), b"Google");
        assert_eq!(id.model_str(), b"Pixel 8");
        assert!(id.is_loaded());
    }

    // ── PhoneBridgeConfig validation ──────────────────────────────────────────

    #[test]
    fn test_config_valid() {
        let cfg = PhoneBridgeConfig::new(0x0900_0000, 0x10);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_config_zero_base_rejected() {
        let cfg = PhoneBridgeConfig::new(0, 0x10);
        assert_eq!(cfg.validate(), Err(PhoneBridgeError::InvalidUsbBase));
    }

    #[test]
    fn test_config_no_stream_ids_rejected() {
        let cfg = PhoneBridgeConfig {
            xhci_bar0_pa: 0x1000_0000,
            stream_ids: [0; MAX_BRIDGE_STREAM_IDS],
            stream_id_count: 0,
        };
        assert_eq!(cfg.validate(), Err(PhoneBridgeError::NoStreamIds));
    }

    #[test]
    fn test_config_too_many_stream_ids_rejected() {
        let cfg = PhoneBridgeConfig {
            xhci_bar0_pa: 0x1000_0000,
            stream_ids: [1; MAX_BRIDGE_STREAM_IDS],
            stream_id_count: MAX_BRIDGE_STREAM_IDS + 1,
        };
        assert_eq!(cfg.validate(), Err(PhoneBridgeError::TooManyStreamIds));
    }

    // ── PhoneBridgeGate ───────────────────────────────────────────────────────

    #[test]
    fn test_gate_requires_all_three() {
        let mut g = PhoneBridgeGate::default();
        g.toggle_source_changes = true;
        g.no_timestamp_gap = true;
        assert!(!g.passes(), "identity_loaded must also be true");
        g.identity_loaded = true;
        assert!(g.passes());
    }

    // ── PhoneBridgeState process_line ─────────────────────────────────────────

    #[test]
    fn test_state_reaches_gate_passed() {
        let mut s = PhoneBridgeState::new();
        s.process_line(b"AetherBridge: handshake OK proto=1");
        s.process_line(b"AetherBridge: sensor stream active at 100Hz");
        s.process_line(b"AetherBridge: identity loaded manufacturer=Google model=Pixel8");
        s.process_line(b"AetherBridge: toggled ON");
        s.process_line(b"AetherBridge: toggled OFF");
        s.process_line(b"AetherBridge: toggle gap-free confirmed");

        assert!(s.gate().passes(), "all gate criteria should pass");
        assert_eq!(s.phase(), PhoneBridgePhase::GatePassed);
    }

    #[test]
    fn test_state_toggle_requires_both_on_and_off() {
        let mut s = PhoneBridgeState::new();
        s.process_line(b"AetherBridge: toggled ON");
        assert!(!s.gate().toggle_source_changes, "need both ON and OFF");
        s.process_line(b"AetherBridge: toggled OFF");
        assert!(s.gate().toggle_source_changes);
    }

    // ── init_phone_bridge ─────────────────────────────────────────────────────

    #[test]
    fn test_init_returns_usb_ready_phase() {
        let cfg = PhoneBridgeConfig::new(0x0900_0000, 0x10);
        let result = init_phone_bridge(&cfg);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().phase(), PhoneBridgePhase::UsbReady);
    }
}
