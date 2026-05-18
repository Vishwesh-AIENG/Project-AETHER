// ch47: Virtual Sensors and Modem — Live
//
// This module makes the paravirtualized sensor suite and virtual modem
// "live" — observable by Android's Sensor HAL and RIL — by wiring them
// to two communication channels:
//
//   1. AETHER_SENSOR_READ HVC (0x8600_0004) — Android's kernel-space Sensor
//      HAL calls this hypercall once per sensor read event. The hypervisor
//      samples the VirtualSensorSuite (ch12) and returns three f32 axis
//      values packed into guest registers x1–x3.
//
//   2. Paravirt serial port — a 4 KiB shared-memory page at AETHER_MODEM_IPA.
//      Android's RIL kernel module maps this page and writes AT commands to
//      CMD_BUF; the hypervisor processes them via VirtualModem::process_command()
//      (ch12) and writes the response to RESP_BUF. Polling occurs on every
//      WFI exit so the RIL experiences sub-millisecond latency.
//
// ── SMCCC HVC Function IDs ────────────────────────────────────────────────────
//
// AETHER vendor range: 0x8600_0001 – 0x8600_0006
// (SMCCC DEN0028, bit[31]=1 SMC64, bits[29:24]=0x06 Std Hyp Service)
//
//   0x8600_0001  GET_VERSION      → x0=0, x1=AETHER_VERSION (major<<16|minor)
//   0x8600_0002  BRIDGE_MODE_GET  → x0=0, x1=0 (SoftwareModel) or 1 (PhoneBridge)
//   0x8600_0003  BRIDGE_MODE_SET  → x1=mode; x0=0 ok / -1 invalid
//   0x8600_0004  SENSOR_READ      → x1=SensorId; x0=0 ok, x1=x_bits, x2=y_bits, x3=z_bits
//   0x8600_0005  UPDATE_STAGE     → stub (implemented in ch65)
//   0x8600_0006  DIAG_LOG_READ    → stub (implemented in ch68)
//
// Calling convention (SMCCC §5.2):
//   x0 = function ID (in)  / return status (out): 0=success, 0xFFFF…=not-supported
//   x1–x3 = arguments (in) / return data (out)
//
// ── Paravirt Modem Shared Memory (AETHER_MODEM_IPA) ──────────────────────────
//
// Physical layout within the 4 KiB page at AETHER_MODEM_IPA:
//
//   Offset 0x000  cmd_ready  u32  Android writes 1 when AT command is ready
//   Offset 0x004  cmd_len    u32  Byte count of command in cmd_buf
//   Offset 0x008  cmd_buf    256B AT command bytes (no trailing CR/LF needed)
//   Offset 0x200  resp_ready u32  Hypervisor writes 1 when response is ready
//   Offset 0x204  resp_len   u32  Byte count of response in resp_buf
//   Offset 0x208  resp_buf   256B AT response (3GPP TS 27.007 §5.1 format)
//
// Read path (hypervisor on WFI exit):
//   1. DC IVAC base_ipa, DSB ISH          — invalidate shared page
//   2. Read cmd_ready; if 0, skip
//   3. Copy cmd_buf[0..cmd_len] → local buffer
//   4. Write volatile cmd_ready = 0, DSB ISH
//   5. VirtualModem::process_command() → resp bytes
//   6. Copy resp bytes → resp_buf, write resp_len
//   7. DC CIVAC resp region, DSB ISH      — clean to PoC
//   8. Write volatile resp_ready = 1, DSB ISH
//
// ── Gate ─────────────────────────────────────────────────────────────────────
//
// VirtualSensorsAndModemGate:
//   accel_visible  = logcat contains "android.sensor.accelerometer"
//   gyro_visible   = logcat contains "android.sensor.gyroscope"
//   mag_visible    = logcat contains "android.sensor.magnetic_field"
//   no_sim_shown   = logcat contains "SIM_NOT_INSERTED" (RIL reports no SIM)
//
// Shell verification:
//   adb shell dumpsys sensorservice | grep -E "accelerometer|gyroscope|magnetic_field"
//   adb shell getprop gsm.sim.state   → "ABSENT"
//
// ── References ───────────────────────────────────────────────────────────────
//
//   SMCCC DEN0028 §5.2        — SMCCC calling convention, OEN field encoding
//   3GPP TS 27.007 §8.12      — AT+CPIN command (SIM PIN / SIM NOT INSERTED)
//   3GPP TS 27.007 §5.4.7     — AT+CIMI (IMSI; ERROR when no SIM)
//   Android Sensor HAL HAL3.0 — hardware/interfaces/sensors/2.1/
//   Android RIL               — hardware/ril/libril/
//   ARM ARM DDI0487 §D1.10    — EL2 stage-2 shared memory and cache maintenance
//   Bosch BMI160 DS000 r1.2   — accelerometer and gyroscope noise parameters

// ─────────────────────────────────────────────────────────────────────────────
// SMCCC HVC function IDs — AETHER vendor range
// ─────────────────────────────────────────────────────────────────────────────

/// GET_VERSION: returns AETHER_VERSION in x1.
pub const AETHER_HVC_GET_VERSION: u64 = 0x8600_0001;
/// BRIDGE_MODE_GET: returns current BridgeMode in x1 (0=Software, 1=PhoneBridge).
pub const AETHER_HVC_BRIDGE_MODE_GET: u64 = 0x8600_0002;
/// BRIDGE_MODE_SET: x1=0 for SoftwareModel, x1=1 for PhoneBridge.
pub const AETHER_HVC_BRIDGE_MODE_SET: u64 = 0x8600_0003;
/// SENSOR_READ: x1=HvcSensorId; returns axis data in x1–x3 as f32 bit patterns.
pub const AETHER_HVC_SENSOR_READ: u64 = 0x8600_0004;
/// UPDATE_STAGE: stub; implemented in ch65 (OTA update).
pub const AETHER_HVC_UPDATE_STAGE: u64 = 0x8600_0005;
/// DIAG_LOG_READ: stub; implemented in ch68 (diagnostics).
pub const AETHER_HVC_DIAG_LOG_READ: u64 = 0x8600_0006;

/// First and last AETHER HVC function IDs. Used for range checking.
pub const AETHER_HVC_FIRST: u64 = AETHER_HVC_GET_VERSION;
pub const AETHER_HVC_LAST: u64 = AETHER_HVC_DIAG_LOG_READ;

/// SMCCC success return value (x0 = 0).
pub const SMCCC_SUCCESS: u64 = 0;
/// SMCCC "not supported" return value (x0 = 0xFFFF_FFFF_FFFF_FFFF, i.e. −1).
pub const SMCCC_NOT_SUPPORTED: u64 = 0xFFFF_FFFF_FFFF_FFFF;
/// SMCCC "invalid parameter" return value (x0 = 0xFFFF_FFFF_FFFF_FFFE, i.e. −2).
pub const SMCCC_INVALID_PARAMETER: u64 = 0xFFFF_FFFF_FFFF_FFFE;

/// Packed AETHER hypervisor version returned by GET_VERSION.
/// Encoding: bits[31:16] = major, bits[15:0] = minor.
pub const AETHER_VERSION: u64 = (0u64 << 16) | 1u64; // 0.1

// ─────────────────────────────────────────────────────────────────────────────
// HvcSensorId — sensor selector argument for AETHER_HVC_SENSOR_READ (x1)
// ─────────────────────────────────────────────────────────────────────────────

/// Sensor identifier passed in x1 for the AETHER_HVC_SENSOR_READ hypercall.
///
/// Maps directly to the Android Sensor type constants used by the HAL:
///   SENSOR_TYPE_ACCELEROMETER    = 1  → Accelerometer (0 here, 0-based for HVC)
///   SENSOR_TYPE_GYROSCOPE        = 4  → Gyroscope
///   SENSOR_TYPE_MAGNETIC_FIELD   = 2  → Magnetometer
///   SENSOR_TYPE_PROXIMITY        = 8  → Proximity
///
/// AETHER uses a compact 0-based encoding in the HVC interface to avoid
/// allocating the full Android sensor-type namespace in x1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum HvcSensorId {
    /// Bosch BMI160 three-axis accelerometer model. Returns m/s² on all axes.
    Accelerometer = 0,
    /// Bosch BMI160 three-axis gyroscope model with random-walk bias. Returns dps.
    Gyroscope = 1,
    /// Bosch BMM150 three-axis magnetometer model. Returns µT on all axes.
    Magnetometer = 2,
    /// Virtual proximity sensor. Always returns Far (z_bits = 0.0f32 bits, x=y=0).
    Proximity = 3,
}

impl HvcSensorId {
    /// Decode a raw x1 register value. Returns `None` for unknown sensor IDs.
    #[inline]
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0 => Some(Self::Accelerometer),
            1 => Some(Self::Gyroscope),
            2 => Some(Self::Magnetometer),
            3 => Some(Self::Proximity),
            _ => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Paravirt modem shared-memory constants
// ─────────────────────────────────────────────────────────────────────────────

/// IPA of the 4 KiB shared modem page.
///
/// Chosen in the QEMU virt address-space gap between the PL011 UART
/// (0x0900_0000) and DRAM (0x4000_0000). Not used by any QEMU built-in device.
/// The Android kernel module (AETHER_MODEM_IPA) maps this page as device
/// memory using `/dev/mem` or a dedicated kernel driver.
pub const AETHER_MODEM_IPA: u64 = 0x0B00_0000;

// Byte offsets within the 4 KiB shared page.
/// u32: Android sets to 1 when a command is waiting in CMD_BUF.
pub const MODEM_OFF_CMD_READY: usize = 0x000;
/// u32: byte count of the AT command in CMD_BUF.
pub const MODEM_OFF_CMD_LEN: usize = 0x004;
/// AT command bytes (no trailing CR/LF required by the hypervisor).
pub const MODEM_OFF_CMD_BUF: usize = 0x008;
/// u32: hypervisor sets to 1 when the response is ready in RESP_BUF.
pub const MODEM_OFF_RESP_READY: usize = 0x200;
/// u32: byte count of the AT response in RESP_BUF.
pub const MODEM_OFF_RESP_LEN: usize = 0x204;
/// AT response bytes (3GPP TS 27.007 §5.1 framing).
pub const MODEM_OFF_RESP_BUF: usize = 0x208;

/// Maximum bytes in CMD_BUF and RESP_BUF respectively.
pub const MODEM_CMD_BUF_MAX: usize = 256;
pub const MODEM_RESP_BUF_MAX: usize = 256;

// ─────────────────────────────────────────────────────────────────────────────
// ParavirtSerialPort — EL2 view of the shared modem page
// ─────────────────────────────────────────────────────────────────────────────

/// EL2-side interface to the paravirt modem shared-memory page.
///
/// Android's RIL kernel driver writes AT commands to CMD_BUF and polls
/// RESP_READY. The hypervisor processes commands on WFI exits via
/// `poll_and_process()`.
pub struct ParavirtSerialPort {
    /// IPA (= PA for identity-mapped EL2 regions) of the shared page.
    base_ipa: u64,
}

impl ParavirtSerialPort {
    pub const fn new(base_ipa: u64) -> Self {
        Self { base_ipa }
    }

    /// Poll CMD_BUF for a pending AT command. If found, clears CMD_READY,
    /// copies the command bytes into `out_cmd`, and returns the length.
    /// Returns 0 when no command is pending.
    ///
    /// # Safety
    /// `base_ipa` must resolve to a valid NormalRw Stage-2 page accessible
    /// from EL2. Must not be called concurrently with Android writing CMD_BUF.
    pub unsafe fn poll_command(&self, out_cmd: &mut [u8; MODEM_CMD_BUF_MAX]) -> usize {
        let base = self.base_ipa as *mut u8;
        unsafe {
            // Invalidate the shared page from D-cache to ensure we read Android's
            // writes rather than a stale EL2 cache line.
            // ARM ARM §D5.5.2: DC IVAC invalidates to PoC.
            core::arch::asm!(
                "dc ivac, {0}",
                "dsb ish",
                in(reg) base,
                options(nostack, nomem)
            );
            let cmd_ready = core::ptr::read_volatile(
                base.add(MODEM_OFF_CMD_READY) as *const u32,
            );
            if cmd_ready == 0 {
                return 0;
            }
            let raw_len = core::ptr::read_volatile(
                base.add(MODEM_OFF_CMD_LEN) as *const u32,
            ) as usize;
            let cmd_len = raw_len.min(MODEM_CMD_BUF_MAX);
            core::ptr::copy_nonoverlapping(
                base.add(MODEM_OFF_CMD_BUF),
                out_cmd.as_mut_ptr(),
                cmd_len,
            );
            // Clear cmd_ready so Android knows the command was consumed.
            core::ptr::write_volatile(base.add(MODEM_OFF_CMD_READY) as *mut u32, 0);
            core::arch::asm!("dsb ish", options(nostack, nomem));
            cmd_len
        }
    }

    /// Write an AT response into RESP_BUF and signal Android via RESP_READY.
    ///
    /// # Safety
    /// Same preconditions as `poll_command`. `resp` must be a valid 3GPP
    /// TS 27.007 §5.1 formatted response (starts with `\r\n`, ends with
    /// `OK\r\n` or `ERROR\r\n`).
    pub unsafe fn write_response(&self, resp: &[u8]) {
        let base = self.base_ipa as *mut u8;
        let len = resp.len().min(MODEM_RESP_BUF_MAX);
        unsafe {
            core::ptr::copy_nonoverlapping(
                resp.as_ptr(),
                base.add(MODEM_OFF_RESP_BUF),
                len,
            );
            core::ptr::write_volatile(
                base.add(MODEM_OFF_RESP_LEN) as *mut u32,
                len as u32,
            );
            core::arch::asm!("dsb ish", options(nostack, nomem));
            // Clean to PoC so Android's D-cache sees the response.
            // ARM ARM §D5.5.3: DC CIVAC cleans and invalidates to PoC.
            core::arch::asm!(
                "dc civac, {0}",
                "dsb ish",
                in(reg) base.add(MODEM_OFF_RESP_BUF),
                options(nostack, nomem)
            );
            // Signal Android: set resp_ready last (after DSB), so Android
            // cannot observe resp_ready=1 before the response data is visible.
            core::ptr::write_volatile(
                base.add(MODEM_OFF_RESP_READY) as *mut u32,
                1,
            );
            core::arch::asm!("dsb ish", options(nostack, nomem));
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Global paravirt state — sensors + modem + serial port
//
// Initialized once during hypervisor boot by `init_virtual_sensors_and_modem()`.
// Accessed from exception handlers (single-threaded per core; EL2 entry masks
// IRQs, preventing re-entrant access on the same core).
// ─────────────────────────────────────────────────────────────────────────────

static mut AETHER_PARAVIRT_STATE: Option<crate::paravirt::ParavirtState> = None;
static mut AETHER_MODEM_PORT: ParavirtSerialPort =
    ParavirtSerialPort { base_ipa: AETHER_MODEM_IPA };

/// Return a mutable reference to the global paravirt state.
///
/// # Safety
/// Must only be called from EL2 exception context (IRQs masked). The state
/// must have been initialized by `init_virtual_sensors_and_modem()`.
pub unsafe fn aether_paravirt_mut() -> &'static mut Option<crate::paravirt::ParavirtState> {
    unsafe { &mut *core::ptr::addr_of_mut!(AETHER_PARAVIRT_STATE) }
}

// ─────────────────────────────────────────────────────────────────────────────
// AETHER HVC dispatcher — called from arm64/exception.rs handle_hvc()
// ─────────────────────────────────────────────────────────────────────────────

/// Return `true` if `func_id` belongs to the AETHER vendor HVC range.
///
/// Callers check this before delegating to PSCI dispatch so AETHER calls are
/// never accidentally interpreted as PSCI calls.
#[inline]
pub fn is_aether_hvc(func_id: u64) -> bool {
    func_id >= AETHER_HVC_FIRST && func_id <= AETHER_HVC_LAST
}

/// Dispatch an AETHER vendor HVC call.
///
/// `regs` is the full guest register file (x0–x30). On entry:
///   regs[0] = func_id (already verified to be in the AETHER range)
///   regs[1] = arg1, regs[2] = arg2, regs[3] = arg3
///
/// On return the handler has written the result into regs[0] (status) and
/// optionally regs[1]–regs[3] (return data). ELR_EL2 already points past
/// the HVC instruction; no PC adjustment is needed.
///
/// # Safety
/// Must be called from EL2 exception context with IRQs masked.
pub unsafe fn dispatch_aether_hvc(regs: &mut [u64; 31]) {
    let func_id = regs[0];
    let arg1 = regs[1];

    match func_id {
        AETHER_HVC_GET_VERSION => {
            regs[0] = SMCCC_SUCCESS;
            regs[1] = AETHER_VERSION;
        }

        AETHER_HVC_SENSOR_READ => unsafe { handle_sensor_read(arg1, regs) },

        AETHER_HVC_BRIDGE_MODE_GET => unsafe { handle_bridge_mode_get(regs) },

        AETHER_HVC_BRIDGE_MODE_SET => unsafe { handle_bridge_mode_set(arg1, regs) },

        // Stubs for later chapters — return NOT_SUPPORTED so Android does not
        // block on an unimplemented call.
        AETHER_HVC_UPDATE_STAGE | AETHER_HVC_DIAG_LOG_READ => {
            regs[0] = SMCCC_NOT_SUPPORTED;
        }

        _ => {
            regs[0] = SMCCC_NOT_SUPPORTED;
        }
    }
}

// ── Internal HVC handlers ────────────────────────────────────────────────────

/// Handle AETHER_HVC_SENSOR_READ.
///
/// On entry: regs[1] = HvcSensorId raw value.
/// On success: regs[0]=0, regs[1]=x_bits, regs[2]=y_bits, regs[3]=z_bits
///   where each *_bits is `f32::to_bits()` zero-extended to u64.
///
/// On BridgeModeActive or uninitialised state: regs[0] = SMCCC_NOT_SUPPORTED.
///
/// # Safety
/// Must be called from EL2 exception context.
unsafe fn handle_sensor_read(sensor_id_raw: u64, regs: &mut [u64; 31]) {
    let Some(sensor_id) = HvcSensorId::from_u64(sensor_id_raw) else {
        regs[0] = SMCCC_NOT_SUPPORTED;
        return;
    };

    // SAFETY: called from EL2 exception handler (IRQs masked, single-threaded).
    let state_opt = unsafe { aether_paravirt_mut() };
    let Some(state) = state_opt else {
        regs[0] = SMCCC_NOT_SUPPORTED;
        return;
    };

    match sensor_id {
        HvcSensorId::Accelerometer => match state.sensors.sample_accel() {
            Ok(s) => {
                regs[0] = SMCCC_SUCCESS;
                regs[1] = s.x.to_bits() as u64;
                regs[2] = s.y.to_bits() as u64;
                regs[3] = s.z.to_bits() as u64;
            }
            Err(_) => regs[0] = SMCCC_NOT_SUPPORTED,
        },

        HvcSensorId::Gyroscope => match state.sensors.sample_gyro() {
            Ok(s) => {
                regs[0] = SMCCC_SUCCESS;
                regs[1] = s.x.to_bits() as u64;
                regs[2] = s.y.to_bits() as u64;
                regs[3] = s.z.to_bits() as u64;
            }
            Err(_) => regs[0] = SMCCC_NOT_SUPPORTED,
        },

        HvcSensorId::Magnetometer => match state.sensors.sample_mag() {
            Ok(s) => {
                regs[0] = SMCCC_SUCCESS;
                regs[1] = s.x.to_bits() as u64;
                regs[2] = s.y.to_bits() as u64;
                regs[3] = s.z.to_bits() as u64;
            }
            Err(_) => regs[0] = SMCCC_NOT_SUPPORTED,
        },

        HvcSensorId::Proximity => {
            // Virtual proximity always reports Far (0.0 cm = no nearby object).
            // Phone Bridge Mode does not affect proximity (ch12 design decision).
            let far_bits = 0.0f32.to_bits() as u64;
            regs[0] = SMCCC_SUCCESS;
            regs[1] = far_bits; // x = proximity value (cm); 0 = Far
            regs[2] = 0;
            regs[3] = 0;
        }
    }
}

/// Handle AETHER_HVC_BRIDGE_MODE_GET.
///
/// Returns the current BridgeMode in regs[1]: 0=SoftwareModel, 1=PhoneBridge.
///
/// # Safety
/// Must be called from EL2 exception context.
unsafe fn handle_bridge_mode_get(regs: &mut [u64; 31]) {
    let state_opt = unsafe { aether_paravirt_mut() };
    let Some(state) = state_opt else {
        regs[0] = SMCCC_NOT_SUPPORTED;
        return;
    };
    regs[0] = SMCCC_SUCCESS;
    regs[1] = match state.sensors.bridge_mode() {
        crate::paravirt::BridgeMode::SoftwareModel => 0,
        crate::paravirt::BridgeMode::PhoneBridge => 1,
    };
}

/// Handle AETHER_HVC_BRIDGE_MODE_SET.
///
/// `arg1` = 0 → SoftwareModel; 1 → PhoneBridge. Any other value → INVALID_PARAMETER.
///
/// # Safety
/// Must be called from EL2 exception context.
unsafe fn handle_bridge_mode_set(arg1: u64, regs: &mut [u64; 31]) {
    let mode = match arg1 {
        0 => crate::paravirt::BridgeMode::SoftwareModel,
        1 => crate::paravirt::BridgeMode::PhoneBridge,
        _ => {
            regs[0] = SMCCC_INVALID_PARAMETER;
            return;
        }
    };
    let state_opt = unsafe { aether_paravirt_mut() };
    let Some(state) = state_opt else {
        regs[0] = SMCCC_NOT_SUPPORTED;
        return;
    };
    state.sensors.set_bridge_mode(mode);
    regs[0] = SMCCC_SUCCESS;
}

// ─────────────────────────────────────────────────────────────────────────────
// Paravirt modem polling — called from handle_wfx() on every WFI exit
// ─────────────────────────────────────────────────────────────────────────────

/// Poll the paravirt modem shared page and process any pending AT command.
///
/// Called from `arm64::exception::handle_wfx()` on every WFI trap so that
/// Android's RIL experiences sub-millisecond AT command latency.
///
/// # Safety
/// Must be called from EL2 with IRQs masked. `AETHER_PARAVIRT_STATE` and
/// `AETHER_MODEM_PORT` must have been initialised by
/// `init_virtual_sensors_and_modem()`.
pub unsafe fn poll_modem_on_wfi() {
    // SAFETY: EL2 exception context, IRQs masked.
    let port = unsafe { &*core::ptr::addr_of!(AETHER_MODEM_PORT) };
    let state_opt = unsafe { aether_paravirt_mut() };
    let Some(state) = state_opt else {
        return;
    };

    let mut cmd_buf = [0u8; MODEM_CMD_BUF_MAX];
    // SAFETY: AETHER_MODEM_IPA is Stage-2 mapped NormalRw; IRQs masked.
    let cmd_len = unsafe { port.poll_command(&mut cmd_buf) };
    if cmd_len == 0 {
        return;
    }

    let mut resp = [0u8; crate::paravirt::AT_RESP_SIZE];
    let resp_len = state
        .modem
        .process_command(&cmd_buf[..cmd_len], &mut resp)
        .unwrap_or_else(|_| {
            let err = b"\r\nERROR\r\n";
            resp[..err.len()].copy_from_slice(err);
            err.len()
        });

    // SAFETY: same as poll_command.
    unsafe { port.write_response(&resp[..resp_len]) };
}

// ─────────────────────────────────────────────────────────────────────────────
// Config / gate / error / state types
// ─────────────────────────────────────────────────────────────────────────────

/// Errors returned by `init_virtual_sensors_and_modem()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VirtualSensorsAndModemError {
    /// The supplied IMEI failed ISO/IEC 7812-1 Luhn validation.
    InvalidImei,
    /// `sensor_odr_hz` is not exactly 100. Android Sensor HAL expects 100 Hz ODR.
    InvalidOdr,
    /// `modem_ipa` is not 4 KiB aligned.
    ModemIpaNotAligned,
    /// `prng_seed` is zero — Xorshift64 requires a non-zero seed.
    ZeroPrngSeed,
}

/// Configuration for the virtual sensor + modem subsystem.
#[derive(Clone, Copy, Debug)]
pub struct VirtualSensorsAndModemConfig {
    /// 15-digit ASCII IMEI. Validated with Luhn checksum before use.
    pub imei: [u8; 15],
    /// Non-zero seed for the Xorshift64 PRNG (platform entropy source in production).
    pub prng_seed: u64,
    /// IPA of the 4 KiB shared modem page. Must be 4 KiB aligned.
    pub modem_ipa: u64,
    /// Sensor output data rate in Hz. Must be exactly 100.
    pub sensor_odr_hz: u32,
}

impl VirtualSensorsAndModemConfig {
    /// Default configuration using the AETHER_MODEM_IPA and the standard 100 Hz ODR.
    ///
    /// `imei` must be a valid Luhn-checked 15-digit IMEI.
    /// `prng_seed` must be non-zero (from hardware entropy in production).
    pub const fn new(imei: [u8; 15], prng_seed: u64) -> Self {
        Self {
            imei,
            prng_seed,
            modem_ipa: AETHER_MODEM_IPA,
            sensor_odr_hz: 100,
        }
    }

    /// Validate all fields. Returns the first error found.
    pub fn validate(&self) -> Result<(), VirtualSensorsAndModemError> {
        if self.prng_seed == 0 {
            return Err(VirtualSensorsAndModemError::ZeroPrngSeed);
        }
        if self.sensor_odr_hz != 100 {
            return Err(VirtualSensorsAndModemError::InvalidOdr);
        }
        if self.modem_ipa & 0xFFF != 0 {
            return Err(VirtualSensorsAndModemError::ModemIpaNotAligned);
        }
        // IMEI validation — re-checked inside ParavirtState::new() but validated
        // here early so the error type stays consistent with this module.
        crate::paravirt::validate_imei(&self.imei)
            .map_err(|_| VirtualSensorsAndModemError::InvalidImei)
    }
}

/// Gate for Chapter 47.
///
/// Passes when all four criteria are satisfied by Android's logcat output.
#[derive(Clone, Copy, Debug, Default)]
pub struct VirtualSensorsAndModemGate {
    /// `dumpsys sensorservice` lists `android.sensor.accelerometer`.
    pub accel_visible: bool,
    /// `dumpsys sensorservice` lists `android.sensor.gyroscope`.
    pub gyro_visible: bool,
    /// `dumpsys sensorservice` lists `android.sensor.magnetic_field`.
    pub mag_visible: bool,
    /// RIL reports `SIM_NOT_INSERTED`; Android status bar shows "No SIM".
    /// Verified via `adb shell getprop gsm.sim.state` → "ABSENT".
    pub no_sim_shown: bool,
}

impl VirtualSensorsAndModemGate {
    pub fn passes(&self) -> bool {
        self.accel_visible && self.gyro_visible && self.mag_visible && self.no_sim_shown
    }

    /// Partial pass: all three sensors visible (modem may still be initialising).
    pub fn sensors_visible(&self) -> bool {
        self.accel_visible && self.gyro_visible && self.mag_visible
    }
}

/// Boot phase of the virtual-sensors-and-modem subsystem.
///
/// Tracks progression from hypervisor init to full Android observability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VirtualSensorsAndModemPhase {
    /// init_virtual_sensors_and_modem() not yet called.
    NotStarted,
    /// init_virtual_sensors_and_modem() completed; HVC dispatch is live.
    HvcRegistered,
    /// Android Sensor HAL sent first SENSOR_READ HVC; at least one axis data returned.
    SensorHalStarted,
    /// Android RIL sent first AT command via paravirt serial; VirtualModem replied.
    ModemAttached,
    /// All gate criteria satisfied.
    GatePassed,
}

/// UART log signatures from Android logcat used by `VirtualSensorsAndModemState`.
///
/// Each constant is a byte-pattern substring that appears in Android's logcat
/// output on the QEMU serial console.
pub const UART_SIG_ACCEL: &[u8]    = b"android.sensor.accelerometer";
pub const UART_SIG_GYRO: &[u8]     = b"android.sensor.gyroscope";
pub const UART_SIG_MAG: &[u8]      = b"android.sensor.magnetic_field";
pub const UART_SIG_NO_SIM: &[u8]   = b"SIM_NOT_INSERTED";
pub const UART_SIG_SIM_ABSENT: &[u8] = b"gsm.sim.state=ABSENT";

/// Runtime state for the virtual-sensors-and-modem subsystem.
///
/// Feed each line of UART/logcat output into `process_line()` to advance the
/// gate; check `gate()` to see if all criteria are satisfied.
#[derive(Debug)]
pub struct VirtualSensorsAndModemState {
    phase: VirtualSensorsAndModemPhase,
    gate: VirtualSensorsAndModemGate,
}

impl VirtualSensorsAndModemState {
    pub const fn new() -> Self {
        Self {
            phase: VirtualSensorsAndModemPhase::NotStarted,
            gate: VirtualSensorsAndModemGate {
                accel_visible: false,
                gyro_visible: false,
                mag_visible: false,
                no_sim_shown: false,
            },
        }
    }

    /// Feed a UART/logcat line and update the gate accordingly.
    pub fn process_line(&mut self, line: &[u8]) {
        if contains_bytes(line, UART_SIG_ACCEL) {
            self.gate.accel_visible = true;
        }
        if contains_bytes(line, UART_SIG_GYRO) {
            self.gate.gyro_visible = true;
        }
        if contains_bytes(line, UART_SIG_MAG) {
            self.gate.mag_visible = true;
        }
        if contains_bytes(line, UART_SIG_NO_SIM)
            || contains_bytes(line, UART_SIG_SIM_ABSENT)
        {
            self.gate.no_sim_shown = true;
        }

        // Advance phase machine
        self.phase = if self.gate.passes() {
            VirtualSensorsAndModemPhase::GatePassed
        } else if self.gate.no_sim_shown {
            VirtualSensorsAndModemPhase::ModemAttached
        } else if self.gate.sensors_visible() {
            VirtualSensorsAndModemPhase::SensorHalStarted
        } else {
            self.phase
        };
    }

    pub fn gate(&self) -> &VirtualSensorsAndModemGate {
        &self.gate
    }

    pub fn phase(&self) -> VirtualSensorsAndModemPhase {
        self.phase
    }
}

/// O(n × m) byte-pattern search — no heap, no regex. Returns `true` if
/// `pattern` appears as a contiguous substring anywhere in `haystack`.
pub fn contains_bytes(haystack: &[u8], pattern: &[u8]) -> bool {
    if pattern.is_empty() {
        return true;
    }
    if pattern.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(pattern.len())
        .any(|w| w == pattern)
}

// ─────────────────────────────────────────────────────────────────────────────
// Initialisation pipeline
// ─────────────────────────────────────────────────────────────────────────────

/// Kernel defconfig entries required for the AETHER virtual sensor HAL kernel module.
///
/// The `/dev/aether` character device that bridges HVC calls to the Sensor HAL
/// requires these kernel config options. Absent any entry → HAL registers 0 sensors.
pub const SENSOR_KERNEL_CONFIG: &[(&str, &str)] = &[
    ("CONFIG_HVC_DRIVER",    "y"), // Generic HVC driver framework
    ("CONFIG_MISC_DEVICES",  "y"), // misc device registration for /dev/aether
    ("CONFIG_IIO",           "y"), // Industrial I/O subsystem (sensor HAL backend)
    ("CONFIG_IIO_BUFFER",    "y"), // IIO triggered buffer for continuous sensor data
];

/// SELinux policy rules required for the AETHER Sensor HAL.
///
/// Silent failure mode: without these rules, the HAL registers but `open()`
/// on /dev/aether returns EACCES; sensorservice shows 0 sensors in dumpsys.
pub const SENSOR_SELINUX_RULES: &[&str] = &[
    "allow hal_sensors_default aether_device:chr_file { read write ioctl open };",
    "allow sensorservice aether_device:chr_file { read write ioctl open };",
    "allow system_server aether_device:chr_file { read ioctl open };",
];

/// AOSP product packages required for the AETHER virtual sensor HAL.
pub const SENSOR_PRODUCT_PACKAGES: &[&str] = &[
    "android.hardware.sensors@2.1-service.aether", // AIDL Sensor HAL service
    "sensors.aether",                               // HAL implementation .so
    "aether_ril",                                   // AETHER RIL for virtual modem
];

/// Initialise the virtual sensor and modem subsystem.
///
/// Must be called once during AETHER boot, after `ExitBootServices()` and
/// before the first ERET to the Android partition. After this call:
///   • SENSOR_READ HVC dispatch is live (returns BMI160-parameterised samples)
///   • BRIDGE_MODE_GET/SET HVC dispatch is live
///   • Paravirt serial port at `cfg.modem_ipa` is armed for AT command polling
///
/// # Panics in debug / returns Err in release
/// Returns `Err` if configuration is invalid (bad IMEI, zero seed, wrong ODR,
/// misaligned modem IPA). In production, these errors should be treated as
/// fatal — continue booting with a broken sensor HAL is worse than halting.
pub fn init_virtual_sensors_and_modem(
    cfg: &VirtualSensorsAndModemConfig,
) -> Result<VirtualSensorsAndModemState, VirtualSensorsAndModemError> {
    cfg.validate()?;

    let paravirt = crate::paravirt::ParavirtState::new(cfg.imei, cfg.prng_seed)
        .map_err(|_| VirtualSensorsAndModemError::InvalidImei)?;

    // SAFETY: called once during hypervisor boot before any guest runs.
    // No concurrent access possible at this stage.
    unsafe {
        *core::ptr::addr_of_mut!(AETHER_PARAVIRT_STATE) = Some(paravirt);
        *core::ptr::addr_of_mut!(AETHER_MODEM_PORT) = ParavirtSerialPort::new(cfg.modem_ipa);
    }

    let mut state = VirtualSensorsAndModemState::new();
    state.phase = VirtualSensorsAndModemPhase::HvcRegistered;
    Ok(state)
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── HvcSensorId ──────────────────────────────────────────────────────────

    #[test]
    fn test_sensor_id_round_trip() {
        for (raw, expected) in [
            (0u64, HvcSensorId::Accelerometer),
            (1, HvcSensorId::Gyroscope),
            (2, HvcSensorId::Magnetometer),
            (3, HvcSensorId::Proximity),
        ] {
            assert_eq!(HvcSensorId::from_u64(raw), Some(expected));
        }
    }

    #[test]
    fn test_sensor_id_unknown_returns_none() {
        assert!(HvcSensorId::from_u64(4).is_none());
        assert!(HvcSensorId::from_u64(u64::MAX).is_none());
    }

    // ── is_aether_hvc ─────────────────────────────────────────────────────────

    #[test]
    fn test_aether_hvc_range_detected() {
        for id in [
            AETHER_HVC_GET_VERSION,
            AETHER_HVC_BRIDGE_MODE_GET,
            AETHER_HVC_BRIDGE_MODE_SET,
            AETHER_HVC_SENSOR_READ,
            AETHER_HVC_UPDATE_STAGE,
            AETHER_HVC_DIAG_LOG_READ,
        ] {
            assert!(is_aether_hvc(id), "0x{id:08X} should be in AETHER range");
        }
    }

    #[test]
    fn test_psci_not_aether_hvc() {
        // PSCI CPU_ON = 0xC400_0003; must NOT match AETHER range
        assert!(!is_aether_hvc(0xC400_0003));
        assert!(!is_aether_hvc(0x8400_0000));
        assert!(!is_aether_hvc(0));
        assert!(!is_aether_hvc(u64::MAX));
    }

    // ── contains_bytes ────────────────────────────────────────────────────────

    #[test]
    fn test_contains_bytes_found() {
        assert!(contains_bytes(b"android.sensor.accelerometer", b"accelerometer"));
    }

    #[test]
    fn test_contains_bytes_not_found() {
        assert!(!contains_bytes(b"android.sensor.gyroscope", b"accelerometer"));
    }

    #[test]
    fn test_contains_bytes_empty_pattern() {
        assert!(contains_bytes(b"anything", b""));
    }

    #[test]
    fn test_contains_bytes_pattern_longer_than_haystack() {
        assert!(!contains_bytes(b"hi", b"hello world"));
    }

    // ── VirtualSensorsAndModemState process_line ──────────────────────────────

    #[test]
    fn test_state_accel_detected() {
        let mut s = VirtualSensorsAndModemState::new();
        s.process_line(b"I sensorservice: android.sensor.accelerometer active");
        assert!(s.gate().accel_visible);
        assert!(!s.gate().gyro_visible);
    }

    #[test]
    fn test_state_all_sensors_and_no_sim() {
        let mut s = VirtualSensorsAndModemState::new();
        s.process_line(b"android.sensor.accelerometer");
        s.process_line(b"android.sensor.gyroscope");
        s.process_line(b"android.sensor.magnetic_field");
        s.process_line(b"RIL: SIM_NOT_INSERTED");
        assert!(s.gate().passes());
        assert_eq!(s.phase(), VirtualSensorsAndModemPhase::GatePassed);
    }

    #[test]
    fn test_state_sim_absent_property() {
        let mut s = VirtualSensorsAndModemState::new();
        s.process_line(b"gsm.sim.state=ABSENT");
        assert!(s.gate().no_sim_shown);
    }

    // ── VirtualSensorsAndModemGate ────────────────────────────────────────────

    #[test]
    fn test_gate_passes_only_when_all_four_set() {
        let mut g = VirtualSensorsAndModemGate::default();
        g.accel_visible = true;
        g.gyro_visible  = true;
        g.mag_visible   = true;
        assert!(!g.passes(), "passes() must require no_sim_shown");
        g.no_sim_shown = true;
        assert!(g.passes());
    }

    #[test]
    fn test_gate_sensors_visible_partial() {
        let mut g = VirtualSensorsAndModemGate::default();
        g.accel_visible = true;
        g.gyro_visible  = true;
        g.mag_visible   = true;
        assert!(g.sensors_visible());
        assert!(!g.passes());
    }

    // ── VirtualSensorsAndModemConfig validation ───────────────────────────────

    #[test]
    fn test_config_valid() {
        let cfg = VirtualSensorsAndModemConfig::new(*b"490154203237518", 0xDEAD_BEEF_1234_5678);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_config_zero_seed_rejected() {
        let cfg = VirtualSensorsAndModemConfig::new(*b"490154203237518", 0);
        assert_eq!(cfg.validate(), Err(VirtualSensorsAndModemError::ZeroPrngSeed));
    }

    #[test]
    fn test_config_invalid_odr_rejected() {
        let cfg = VirtualSensorsAndModemConfig {
            sensor_odr_hz: 50,
            ..VirtualSensorsAndModemConfig::new(*b"490154203237518", 1)
        };
        assert_eq!(cfg.validate(), Err(VirtualSensorsAndModemError::InvalidOdr));
    }

    #[test]
    fn test_config_misaligned_modem_ipa_rejected() {
        let cfg = VirtualSensorsAndModemConfig {
            modem_ipa: 0x0B00_0001, // not 4 KiB aligned
            ..VirtualSensorsAndModemConfig::new(*b"490154203237518", 1)
        };
        assert_eq!(cfg.validate(), Err(VirtualSensorsAndModemError::ModemIpaNotAligned));
    }

    #[test]
    fn test_config_bad_imei_rejected() {
        let cfg = VirtualSensorsAndModemConfig::new(*b"490154203237517", 1); // wrong check digit
        assert_eq!(cfg.validate(), Err(VirtualSensorsAndModemError::InvalidImei));
    }

    // ── init_virtual_sensors_and_modem ───────────────────────────────────────

    #[test]
    fn test_init_returns_hvc_registered_phase() {
        let cfg = VirtualSensorsAndModemConfig::new(*b"490154203237518", 0xCAFE_BABE_1234_5678);
        let result = init_virtual_sensors_and_modem(&cfg);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().phase(), VirtualSensorsAndModemPhase::HvcRegistered);
    }
}
