//! Progressive RFX decode and encode algorithms ([MS-RDPEGFX] 2.2.4.2).
//!
//! Provides first-pass decode (RLGR1 + progressive dequantization + sign capture)
//! and upgrade-pass decode (SRL/raw routing by DAS sign state, coefficient
//! accumulation) for the RemoteFX Progressive codec.
//!
//! These are pure algorithmic functions operating on coefficient buffers.
//! Tile state management and EGFX integration belong in a higher layer.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::collections::btree_map::Entry;

use ironrdp_pdu::codecs::rfx::EntropyAlgorithm;
use ironrdp_pdu::codecs::rfx::progressive::ComponentCodecQuant;

use crate::dwt_extrapolate::BandInfo;
use crate::rlgr::RlgrError;
use crate::srl;

/// Number of DWT coefficients per component in a 64x64 tile.
pub const COEFFICIENTS_PER_COMPONENT: usize = 4096;

/// Number of subbands in a 3-level DWT decomposition.
pub const NUM_BANDS: usize = 10;

/// DAS (Delta-Analysis State) values for tri-state sign tracking.
///
/// After the first pass, each coefficient position is classified:
/// - `SIGN_ZERO`: coefficient was zero (eligible for SRL upgrade)
/// - `SIGN_POSITIVE`: coefficient was positive (eligible for raw upgrade)
/// - `SIGN_NEGATIVE`: coefficient was negative (eligible for raw upgrade)
pub const SIGN_ZERO: i8 = 0;
pub const SIGN_POSITIVE: i8 = 1;
pub const SIGN_NEGATIVE: i8 = -1;

// ---------------------------------------------------------------------------
// First-pass decode (TILE_SIMPLE / TILE_FIRST)
// ---------------------------------------------------------------------------

/// Decode a first-pass component from RLGR1-encoded data.
///
/// Performs: RLGR1 decode -> base dequantization -> progressive dequantization
/// -> LL3 delta decode -> sign capture.
///
/// # Arguments
/// - `data`: RLGR1-encoded coefficient stream
/// - `base_quant`: base quantization values (from region quant table, `ComponentCodecQuant` format)
/// - `prog_quant`: progressive quantization BitPos values for this quality level
/// - `use_reduce_extrapolate`: whether to use asymmetric band sizes
/// - `coefficients`: output buffer for decoded coefficients (4096 i16)
/// - `sign`: output buffer for DAS sign state (4096 i8)
///
/// # Panics
///
/// Panics if `coefficients` or `sign` has fewer than 4096 elements.
///
/// # Errors
/// Returns `RlgrError` if RLGR decoding fails.
pub fn decode_first_pass(
    data: &[u8],
    base_quant: &ComponentCodecQuant,
    prog_quant: &ComponentCodecQuant,
    use_reduce_extrapolate: bool,
    coefficients: &mut [i16],
    sign: &mut [i8],
) -> Result<(), RlgrError> {
    assert!(coefficients.len() >= COEFFICIENTS_PER_COMPONENT);
    assert!(sign.len() >= COEFFICIENTS_PER_COMPONENT);

    // Step 1: RLGR1 decode into coefficient buffer
    crate::rlgr::decode(EntropyAlgorithm::Rlgr1, data, coefficients)?;

    // Escale : signes relevés sur les valeurs RLGR brutes, avant le décodage différentiel de LL3,
    // comme FreeRDP (`CopyMemory(sign, buffer, …)`) ; LL3 n'utilise pas les signes
    capture_sign(coefficients, sign);

    // Step 2: LL3 differential decoding (reverse delta encoding on last subband)
    let ll3 = ll3_offset(use_reduce_extrapolate);
    crate::subband_reconstruction::decode(&mut coefficients[ll3..COEFFICIENTS_PER_COMPONENT]);

    // Step 3: Base dequantization (shift left by quant - 1)
    dequantize_component_ccq(coefficients, base_quant, use_reduce_extrapolate);

    // Step 4: Progressive dequantization (shift left by BitPos)
    progressive_dequantize(coefficients, prog_quant, use_reduce_extrapolate);

    Ok(())
}

/// Position de bit totale (quantification de base + progressive) de chaque bande, dans l'ordre
/// HL1, LH1, HH1, HL2, LH2, HH2, HL3, LH3, HH3, LL3 (`progressive_rfx_quant_add` de FreeRDP).
pub fn bit_positions(base_quant: &ComponentCodecQuant, prog_quant: &ComponentCodecQuant) -> [u8; NUM_BANDS] {
    core::array::from_fn(|b| base_quant.for_band(b).saturating_add(prog_quant.for_band(b)))
}

/// Passe d'amélioration illisible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpgradeError {
    /// Une bande perdrait de la précision (position de bit en hausse) : FreeRDP refuse la tuile.
    BitPosIncreased { band: usize, previous: u8, current: u8 },
    /// Position de bit nulle : décalage négatif.
    ZeroBitPos { band: usize },
}

impl core::fmt::Display for UpgradeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BitPosIncreased { band, previous, current } => {
                write!(f, "bande {band} : position de bit {previous} -> {current}")
            }
            Self::ZeroBitPos { band } => write!(f, "bande {band} : position de bit nulle"),
        }
    }
}

fn sign_of(v: i64) -> i8 {
    match v.cmp(&0) {
        core::cmp::Ordering::Greater => SIGN_POSITIVE,
        core::cmp::Ordering::Less => SIGN_NEGATIVE,
        core::cmp::Ordering::Equal => SIGN_ZERO,
    }
}

/// Decode an upgrade-pass component from SRL and raw data streams.
///
/// Escale : réécrit d'après FreeRDP (`progressive_rfx_upgrade_component` /
/// `progressive_rfx_upgrade_block`) :
/// - un seul lecteur SRL et un seul lecteur RAW pour toute la composante, bande après bande
///   (l'ancienne version les recréait à chaque bande et relisait donc le début du flux) ;
/// - `numBits` = ancienne position de bit (base + progressive) - nouvelle, décalage = nouvelle - 1 ;
/// - coefficient de signe non nul : `numBits` bits bruts ajoutés (signe positif) ou retranchés ;
///   signe nul : valeur SRL, qui fixe le signe pour les passes suivantes ;
/// - LL3 : toujours lu en brut et ajouté, sans SRL ni signe (l'ancienne version passait par le SRL
///   pour les coefficients LL3 nuls et faussait la couleur moyenne de la tuile).
///
/// # Panics
///
/// Panics if `coefficients` or `sign` has fewer than 4096 elements.
///
/// # Errors
///
/// Positions de bit incohérentes (voir [`UpgradeError`]) : rien n'est modifié.
pub fn decode_upgrade_pass(
    srl_data: &[u8],
    raw_data: &[u8],
    prev_bit_pos: &[u8; NUM_BANDS],
    curr_bit_pos: &[u8; NUM_BANDS],
    use_reduce_extrapolate: bool,
    coefficients: &mut [i16],
    sign: &mut [i8],
) -> Result<(), UpgradeError> {
    assert!(coefficients.len() >= COEFFICIENTS_PER_COMPONENT);
    assert!(sign.len() >= COEFFICIENTS_PER_COMPONENT);

    for band in 0..NUM_BANDS {
        let (previous, current) = (prev_bit_pos[band], curr_bit_pos[band]);
        if previous < current {
            return Err(UpgradeError::BitPosIncreased { band, previous, current });
        }
        if current == 0 {
            return Err(UpgradeError::ZeroBitPos { band });
        }
    }

    let bands = get_band_layout(use_reduce_extrapolate);
    let mut srl = srl::SrlDecoder::new(srl_data);
    let mut raw = RawBitReader::new(raw_data);

    for (band_idx, band) in bands.iter().enumerate() {
        let num_bits = u32::from(prev_bit_pos[band_idx] - curr_bit_pos[band_idx]);
        if num_bits == 0 {
            continue;
        }
        let shift = u32::from(curr_bit_pos[band_idx] - 1).min(40);

        for i in band.offset..band.offset + band.count() {
            let input = if band_idx == 9 {
                // LL3 : toujours brut, toujours ajouté
                i64::from(raw.read_bits(num_bits))
            } else if sign[i] > 0 {
                i64::from(raw.read_bits(num_bits))
            } else if sign[i] < 0 {
                -i64::from(raw.read_bits(num_bits))
            } else {
                let v = i64::from(srl.read(num_bits));
                sign[i] = sign_of(v);
                v
            };
            if input != 0 {
                coefficients[i] = clamp_i16_wide(i64::from(coefficients[i]) + input * (1i64 << shift));
            }
        }
    }

    Ok(())
}

/// Escale : passe d'amélioration d'une composante, symétrique de [`decode_upgrade_pass`]
/// (encodeur de test, fidèle au décodeur de FreeRDP).
///
/// `quantized` : coefficients après DWT et quantification de base (`quant - 1`), soit les valeurs
/// que transmettrait la pleine qualité (voir [`quantize_for_upgrade`]). `sign` est l'état du
/// décodeur avant la passe et est mis à jour comme le fera le décodeur. Positions de bit :
/// progressives seulement (la quantification de base ne change pas d'une passe à l'autre).
/// Retourne `(srl, raw)`.
pub fn encode_upgrade_pass(
    quantized: &[i16],
    prev_prog_quant: &ComponentCodecQuant,
    curr_prog_quant: &ComponentCodecQuant,
    sign: &mut [i8],
    use_reduce_extrapolate: bool,
) -> (Vec<u8>, Vec<u8>) {
    let bands = get_band_layout(use_reduce_extrapolate);
    let mut srl = srl::SrlEncoder::new();
    let mut raw = RawBitWriter::new();

    for (band_idx, band) in bands.iter().enumerate() {
        let (prev, curr) = (prev_prog_quant.for_band(band_idx), curr_prog_quant.for_band(band_idx));
        let num_bits = u32::from(prev.saturating_sub(curr));
        if num_bits == 0 {
            continue;
        }
        let mask = (1u32 << num_bits) - 1;
        for i in band.offset..band.offset + band.count() {
            let v = i32::from(quantized[i]);
            if band_idx == 9 {
                // LL3 : bits de poids faible de la division arrondie vers -inf (complément à deux)
                raw.write_bits(u32::from_ne_bytes((v >> curr).to_ne_bytes()) & mask, num_bits);
            } else if sign[i] != 0 {
                raw.write_bits((v.unsigned_abs() >> curr) & mask, num_bits);
            } else {
                let mag = i64::from(v.unsigned_abs() >> curr);
                let value = if v < 0 { -mag } else { mag };
                srl.push(clamp_i16_wide(value), num_bits);
                sign[i] = sign_of(value);
            }
        }
    }

    (srl.finish(), raw.finish())
}

/// Escale : coefficients quantifiés (DWT + quantification de base) d'une composante spatiale,
/// entrée de [`encode_upgrade_pass`]. Modifie `coefficients` en place.
///
/// # Panics
///
/// Panics if `coefficients` has fewer than 4096 elements.
pub fn quantize_for_upgrade(coefficients: &mut [i16], base_quant: &ComponentCodecQuant, use_reduce_extrapolate: bool) {
    let mut temp = [0i16; COEFFICIENTS_PER_COMPONENT];
    if use_reduce_extrapolate {
        crate::dwt_extrapolate::encode(coefficients, &mut temp);
    } else {
        crate::dwt::encode(coefficients, &mut temp);
    }
    quantize_component_ccq(coefficients, base_quant, use_reduce_extrapolate);
}

// ---------------------------------------------------------------------------
// Progressive (de)quantization
// ---------------------------------------------------------------------------

/// Apply progressive dequantization: left-shift each band by its BitPos value.
///
/// For non-LL3 bands, this shifts the absolute value (preserving sign).
/// For LL3, this is a simple left shift (floor toward negative infinity).
fn progressive_dequantize(coefficients: &mut [i16], prog_quant: &ComponentCodecQuant, use_reduce_extrapolate: bool) {
    let bands = get_band_layout(use_reduce_extrapolate);

    for (band_idx, band) in bands.iter().enumerate() {
        let bit_pos = prog_quant.for_band(band_idx);
        if bit_pos == 0 {
            continue;
        }

        let is_ll3 = band_idx == 9;
        let start = band.offset;
        let end = start + band.count();

        if is_ll3 {
            // LL3: simple left shift (floor toward negative infinity)
            for coeff in &mut coefficients[start..end] {
                *coeff = clamp_i16(i32::from(*coeff) << i32::from(bit_pos));
            }
        } else {
            // Other bands: shift absolute value, preserve sign
            for coeff in &mut coefficients[start..end] {
                let val = i32::from(*coeff);
                if val >= 0 {
                    *coeff = clamp_i16(val << i32::from(bit_pos));
                } else {
                    *coeff = clamp_i16(-((-val) << i32::from(bit_pos)));
                }
            }
        }
    }
}

/// Apply progressive quantization: right-shift each band by its BitPos value.
///
/// Inverse of `progressive_dequantize`.
pub fn progressive_quantize(coefficients: &mut [i16], prog_quant: &ComponentCodecQuant, use_reduce_extrapolate: bool) {
    let bands = get_band_layout(use_reduce_extrapolate);

    for (band_idx, band) in bands.iter().enumerate() {
        let bit_pos = prog_quant.for_band(band_idx);
        if bit_pos == 0 {
            continue;
        }

        let is_ll3 = band_idx == 9;
        let start = band.offset;
        let end = start + band.count();

        if is_ll3 {
            // LL3: floor division (right shift)
            for coeff in &mut coefficients[start..end] {
                *coeff >>= bit_pos;
            }
        } else {
            // Other bands: truncation toward zero
            for coeff in &mut coefficients[start..end] {
                let val = i32::from(*coeff);
                if val >= 0 {
                    *coeff = clamp_i16(val >> i32::from(bit_pos));
                } else {
                    *coeff = clamp_i16(-((-val) >> i32::from(bit_pos)));
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Server-side encode pipeline
// ---------------------------------------------------------------------------

/// Encode a first-pass component from spatial-domain coefficients.
///
/// Pipeline: forward DWT -> base quantization -> progressive quantization
/// -> LL3 delta encode -> RLGR1 encode.
///
/// Returns the number of bytes written to `output`.
///
/// # Arguments
/// - `coefficients`: spatial-domain coefficients (4096 i16, modified in-place)
/// - `output`: output buffer for RLGR1-encoded data
/// - `base_quant`: base quantization values
/// - `prog_quant`: progressive quantization BitPos values for this quality level
/// - `use_reduce_extrapolate`: DWT mode flag
///
/// # Panics
///
/// Panics if `coefficients` has fewer than 4096 elements.
///
/// # Errors
/// Returns `RlgrError` if RLGR encoding fails.
pub fn encode_first_pass(
    coefficients: &mut [i16],
    output: &mut [u8],
    base_quant: &ComponentCodecQuant,
    prog_quant: &ComponentCodecQuant,
    use_reduce_extrapolate: bool,
) -> Result<usize, RlgrError> {
    assert!(coefficients.len() >= COEFFICIENTS_PER_COMPONENT);

    let mut temp = [0i16; COEFFICIENTS_PER_COMPONENT];

    // Step 1: Forward DWT
    if use_reduce_extrapolate {
        crate::dwt_extrapolate::encode(coefficients, &mut temp);
    } else {
        crate::dwt::encode(coefficients, &mut temp);
    }

    // Step 2: Base quantization (right-shift by quant - 1)
    quantize_component_ccq(coefficients, base_quant, use_reduce_extrapolate);

    // Step 3: Progressive quantization (right-shift by BitPos)
    progressive_quantize(coefficients, prog_quant, use_reduce_extrapolate);

    // Step 4: LL3 delta encoding
    crate::subband_reconstruction::encode(&mut coefficients[ll3_offset(use_reduce_extrapolate)..]);

    // Step 5: RLGR1 entropy encode
    crate::rlgr::encode(EntropyAlgorithm::Rlgr1, coefficients, output)
}

/// Base quantization using `ComponentCodecQuant` (progressive format).
///
/// Each band is right-shifted by `(quant_value - 1)`. Inverse of `dequantize_component_ccq`.
fn quantize_component_ccq(coefficients: &mut [i16], quant: &ComponentCodecQuant, use_reduce_extrapolate: bool) {
    let bands = get_band_layout(use_reduce_extrapolate);

    for (band_idx, band) in bands.iter().enumerate() {
        let q = quant.for_band(band_idx);
        let factor = q.saturating_sub(1);
        if factor > 0 {
            let start = band.offset;
            let end = start + band.count();
            for coeff in &mut coefficients[start..end] {
                // Truncation toward zero (same as classic quantization::encode)
                let val = i32::from(*coeff);
                if val >= 0 {
                    *coeff = clamp_i16(val >> i32::from(factor));
                } else {
                    *coeff = clamp_i16(-((-val) >> i32::from(factor)));
                }
            }
        }
    }
}

/// Encode RGBA pixels to spatial-domain i16 coefficients (RGB to YCbCr).
///
/// Performs ITU-R BT.601 RGB-to-YCbCr conversion on a 64x64 pixel tile.
/// Output is 3 buffers of 4096 i16 coefficients (Y, Cb, Cr) in tile order.
///
/// # Panics
///
/// Panics if `pixels` has fewer than 64 * 64 * 4 = 16384 bytes.
#[expect(clippy::similar_names)]
pub fn rgba_to_ycbcr(pixels: &[u8], y_out: &mut [i16], cb_out: &mut [i16], cr_out: &mut [i16]) {
    assert!(pixels.len() >= 64 * 64 * 4);
    assert!(y_out.len() >= COEFFICIENTS_PER_COMPONENT);
    assert!(cb_out.len() >= COEFFICIENTS_PER_COMPONENT);
    assert!(cr_out.len() >= COEFFICIENTS_PER_COMPONENT);

    for i in 0..64 * 64 {
        let off = i * 4;
        let r = i32::from(pixels[off]);
        let g = i32::from(pixels[off + 1]);
        let b = i32::from(pixels[off + 2]);

        // ITU-R BT.601: Y = 0.299R + 0.587G + 0.114B
        //               Cb = -0.169R - 0.331G + 0.500B
        //               Cr = 0.500R - 0.419G - 0.081B
        // Fixed-point with 16-bit precision
        let y = ((19595 * r + 38470 * g + 7471 * b + 32768) >> 16) - 128;
        let cb = (-11059 * r - 21709 * g + 32768 * b + 32768) >> 16;
        let cr = (32768 * r - 27439 * g - 5329 * b + 32768) >> 16;

        y_out[i] = clamp_i16(y);
        cb_out[i] = clamp_i16(cb);
        cr_out[i] = clamp_i16(cr);
    }
}

/// Base dequantization using `ComponentCodecQuant` (progressive-format quantization).
///
/// Each band is shifted left by `(quant_value - 1)`. Uses `for_band()` to map
/// band indices to quant values, which handles the progressive nibble ordering.
fn dequantize_component_ccq(coefficients: &mut [i16], quant: &ComponentCodecQuant, use_reduce_extrapolate: bool) {
    let bands = get_band_layout(use_reduce_extrapolate);

    for (band_idx, band) in bands.iter().enumerate() {
        let q = quant.for_band(band_idx);
        let factor = i16::from(q).saturating_sub(1);
        if factor > 0 {
            let start = band.offset;
            let end = start + band.count();
            for coeff in &mut coefficients[start..end] {
                *coeff <<= factor;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Sign capture
// ---------------------------------------------------------------------------

/// Capture the tri-state sign of each coefficient into the DAS array.
fn capture_sign(coefficients: &[i16], sign: &mut [i8]) {
    for (s, &c) in sign.iter_mut().zip(coefficients.iter()) {
        *s = match c.cmp(&0) {
            core::cmp::Ordering::Greater => SIGN_POSITIVE,
            core::cmp::Ordering::Less => SIGN_NEGATIVE,
            core::cmp::Ordering::Equal => SIGN_ZERO,
        };
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Get the band layout for the current DWT mode.
fn get_band_layout(use_reduce_extrapolate: bool) -> [BandInfo; NUM_BANDS] {
    if use_reduce_extrapolate {
        crate::dwt_extrapolate::band_layout()
    } else {
        standard_band_layout()
    }
}

/// Standard (non-extrapolate) band layout for a 64x64 tile.
/// Band sizes: 1024 each for level 1, 256 each for level 2, 64 each for level 3.
fn standard_band_layout() -> [BandInfo; NUM_BANDS] {
    let mut off = 0;
    let mut b = |w: usize, h: usize| {
        let info = BandInfo {
            width: w,
            height: h,
            offset: off,
        };
        off += w * h;
        info
    };

    [
        b(32, 32), // HL1: 1024
        b(32, 32), // LH1: 1024
        b(32, 32), // HH1: 1024
        b(16, 16), // HL2: 256
        b(16, 16), // LH2: 256
        b(16, 16), // HH2: 256
        b(8, 8),   // HL3: 64
        b(8, 8),   // LH3: 64
        b(8, 8),   // HH3: 64
        b(8, 8),   // LL3: 64
    ]
}

/// Starting offset of the LL3 subband for delta decoding.
fn ll3_offset(use_reduce_extrapolate: bool) -> usize {
    if use_reduce_extrapolate {
        4015 // reduce-extrapolate: 9x9 = 81 coefficients at offset 4015
    } else {
        4032 // standard: 8x8 = 64 coefficients at offset 4032
    }
}

/// Clamp i64 to i16 range.
#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    reason = "value is clamped to i16 range before cast"
)]
fn clamp_i16_wide(value: i64) -> i16 {
    value.clamp(i64::from(i16::MIN), i64::from(i16::MAX)) as i16
}

/// Clamp i32 to i16 range.
#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    reason = "value is clamped to i16 range before cast"
)]
fn clamp_i16(value: i32) -> i16 {
    value.clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16
}

// ---------------------------------------------------------------------------
// Raw bit I/O for upgrade pass
// ---------------------------------------------------------------------------

/// Writes raw magnitude bits MSB-first to a byte stream.
///
/// Symmetric counterpart of [`RawBitReader`]. Callers are expected to pass
/// `count <= 32` to [`write_bits`](Self::write_bits); the upgrade-pass call
/// site bounds `count` by `prev_bit_pos - curr_bit_pos` which is at most a
/// few bits in practice. `count > 32` reads beyond `u32` width in the shift
/// expression, which is wrap-on-release / panic-on-debug — caller responsibility.
struct RawBitWriter {
    bytes: Vec<u8>,
    current: u8,
    bit_count: u8,
}

impl RawBitWriter {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            current: 0,
            bit_count: 0,
        }
    }

    fn write_bit(&mut self, bit: bool) {
        self.current = (self.current << 1) | u8::from(bit);
        self.bit_count += 1;
        if self.bit_count >= 8 {
            self.bytes.push(self.current);
            self.current = 0;
            self.bit_count = 0;
        }
    }

    /// Write the low `count` bits of `value`, MSB-first. Caller must ensure
    /// `count <= 32` (see type-level docs).
    fn write_bits(&mut self, value: u32, count: u32) {
        debug_assert!(count <= 32, "RawBitWriter::write_bits count must be <= 32");
        for i in (0..count).rev() {
            self.write_bit((value >> i) & 1 != 0);
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.bit_count > 0 {
            self.current <<= 8 - self.bit_count;
            self.bytes.push(self.current);
        }
        self.bytes
    }
}

/// Reads raw magnitude bits MSB-first from a byte stream.
///
/// Past-end-of-stream reads return zero bits rather than an error: a
/// truncated `raw_data` produces zero coefficient magnitudes (no-op upgrade)
/// for the missing positions, matching the FreeRDP reference implementation's
/// tolerance for short truncation in this exact upgrade path.
///
/// Callers are expected to pass `count <= 32` to [`read_bits`](Self::read_bits);
/// the upgrade-pass call site bounds `count` by `prev_bit_pos - curr_bit_pos`
/// which is at most a few bits in practice.
struct RawBitReader<'a> {
    data: &'a [u8],
    byte_idx: usize,
    bit_idx: u8,
}

impl<'a> RawBitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            byte_idx: 0,
            bit_idx: 0,
        }
    }

    /// Read `count` bits MSB-first into a `u32`. Bits past the end of the
    /// underlying stream read as zero.
    fn read_bits(&mut self, count: u32) -> u32 {
        let mut value = 0u32;
        for _ in 0..count {
            value = (value << 1) | u32::from(self.read_bit());
        }
        value
    }

    /// Read one bit. Returns `false` past end-of-stream by design (see
    /// type-level docs).
    fn read_bit(&mut self) -> bool {
        if self.byte_idx >= self.data.len() {
            return false;
        }
        let bit = (self.data[self.byte_idx] >> (7 - self.bit_idx)) & 1 != 0;
        self.bit_idx += 1;
        if self.bit_idx >= 8 {
            self.bit_idx = 0;
            self.byte_idx += 1;
        }
        bit
    }
}

// ---------------------------------------------------------------------------
// Tile state machine
// ---------------------------------------------------------------------------

/// Per-tile progressive state: coefficients, signs, and quality tracking.
///
/// Each tile in a progressive surface maintains this state across decode
/// passes. The first pass (TILE_SIMPLE or TILE_FIRST) initializes the
/// coefficients and signs; subsequent upgrade passes (TILE_UPGRADE)
/// accumulate refinement data.
///
/// Memory per tile: ~37 KB (24 KB coefficients + 12 KB signs + metadata).
pub struct TileState {
    /// Accumulated DWT coefficients per component (Y, Cb, Cr).
    pub coefficients: [[i16; COEFFICIENTS_PER_COMPONENT]; 3],
    /// Tri-state sign tracking per component (DAS array).
    pub sign: [[i8; COEFFICIENTS_PER_COMPONENT]; 3],
    /// Progressive quantization BitPos from the last applied pass.
    pub prog_quant: [ComponentCodecQuant; 3],
    /// Escale : positions de bit totales (base + progressive) de la dernière passe, par
    /// composante et par bande (`tile->yBitPos` … de FreeRDP).
    pub bit_pos: [[u8; NUM_BANDS]; 3],
    /// Base quantization indices (Y, Cb, Cr) into the region's quant table.
    pub quant_idx: [u8; 3],
    /// Progressive pass counter (0 = no data, 1 = first pass complete, 2+ = upgrade).
    pub pass: u16,
    /// Whether the tile was encoded as a difference tile.
    pub is_difference: bool,
    /// Last progressive quality byte (0xFF = full quality).
    pub quality: u8,
    /// Whether reduce-extrapolate DWT is used for this tile's context.
    pub use_reduce_extrapolate: bool,
}

impl TileState {
    /// Create a new tile with zeroed state.
    pub fn new() -> Self {
        Self {
            coefficients: [[0; COEFFICIENTS_PER_COMPONENT]; 3],
            sign: [[0; COEFFICIENTS_PER_COMPONENT]; 3],
            prog_quant: [ComponentCodecQuant::LOSSLESS; 3],
            bit_pos: [[0; NUM_BANDS]; 3],
            quant_idx: [0; 3],
            pass: 0,
            is_difference: false,
            quality: 0,
            use_reduce_extrapolate: false,
        }
    }

    /// Decode a first-pass tile (TILE_SIMPLE or TILE_FIRST).
    ///
    /// Resets this tile's state and decodes three components from RLGR1 data.
    /// After this call, `coefficients` hold DWT-domain values ready for
    /// inverse DWT + color conversion.
    ///
    /// # Arguments
    /// - `component_data`: RLGR1-encoded data for [Y, Cb, Cr]
    /// - `base_quants`: base quantization values for [Y, Cb, Cr]
    /// - `prog_quants`: progressive quantization for [Y, Cb, Cr]
    /// - `quality`: progressive quality byte
    /// - `use_reduce_extrapolate`: DWT mode flag
    ///
    /// # Errors
    /// Returns `RlgrError` if any component's RLGR decode fails.
    pub fn decode_first(
        &mut self,
        component_data: [&[u8]; 3],
        base_quants: [&ComponentCodecQuant; 3],
        prog_quants: [ComponentCodecQuant; 3],
        quant_idx: [u8; 3],
        quality: u8,
        use_reduce_extrapolate: bool,
    ) -> Result<(), RlgrError> {
        self.decode_first_diff(component_data, base_quants, prog_quants, quant_idx, quality, use_reduce_extrapolate, false)
    }

    /// Escale : première passe, éventuellement différentielle (RFX_TILE_DIFFERENCE) : les
    /// coefficients reçus s'ajoutent alors à ceux de la tuile précédente.
    #[expect(clippy::too_many_arguments)]
    pub fn decode_first_diff(
        &mut self,
        component_data: [&[u8]; 3],
        base_quants: [&ComponentCodecQuant; 3],
        prog_quants: [ComponentCodecQuant; 3],
        quant_idx: [u8; 3],
        quality: u8,
        use_reduce_extrapolate: bool,
        difference: bool,
    ) -> Result<(), RlgrError> {
        let previous = if difference && self.pass > 0 { Some(self.coefficients) } else { None };
        self.pass = 1;
        self.quality = quality;
        self.quant_idx = quant_idx;
        self.use_reduce_extrapolate = use_reduce_extrapolate;
        self.is_difference = difference;
        self.prog_quant = prog_quants;

        for c in 0..3 {
            self.bit_pos[c] = bit_positions(base_quants[c], &prog_quants[c]);
            decode_first_pass(
                component_data[c],
                base_quants[c],
                &prog_quants[c],
                use_reduce_extrapolate,
                &mut self.coefficients[c],
                &mut self.sign[c],
            )?;
            if let Some(prev) = &previous {
                for (v, p) in self.coefficients[c].iter_mut().zip(prev[c].iter()) {
                    *v = v.saturating_add(*p);
                }
            }
        }

        Ok(())
    }

    /// Decode an upgrade-pass tile (TILE_UPGRADE).
    ///
    /// Accumulates refinement data into existing coefficients.
    ///
    /// # Arguments
    /// - `srl_data`: SRL-encoded streams for [Y, Cb, Cr]
    /// - `raw_data`: raw bit streams for [Y, Cb, Cr]
    /// - `base_quants`: base quantization for [Y, Cb, Cr] (normalement inchangée)
    /// - `prog_quants`: progressive quantization for this upgrade level
    /// - `quality`: progressive quality byte for this pass
    ///
    /// # Errors
    ///
    /// Positions de bit incohérentes avec la passe précédente : la tuile reste inchangée.
    pub fn decode_upgrade(
        &mut self,
        srl_data: [&[u8]; 3],
        raw_data: [&[u8]; 3],
        base_quants: [&ComponentCodecQuant; 3],
        prog_quants: [ComponentCodecQuant; 3],
        quality: u8,
    ) -> Result<(), UpgradeError> {
        let bit_pos: [[u8; NUM_BANDS]; 3] = core::array::from_fn(|c| bit_positions(base_quants[c], &prog_quants[c]));
        // vérification préalable : une composante refusée ne doit pas laisser les autres à moitié
        // améliorées
        for c in 0..3 {
            for band in 0..NUM_BANDS {
                let (previous, current) = (self.bit_pos[c][band], bit_pos[c][band]);
                if previous < current {
                    return Err(UpgradeError::BitPosIncreased { band, previous, current });
                }
                if current == 0 {
                    return Err(UpgradeError::ZeroBitPos { band });
                }
            }
        }

        for c in 0..3 {
            decode_upgrade_pass(
                srl_data[c],
                raw_data[c],
                &self.bit_pos[c],
                &bit_pos[c],
                self.use_reduce_extrapolate,
                &mut self.coefficients[c],
                &mut self.sign[c],
            )?;
        }

        self.bit_pos = bit_pos;
        self.prog_quant = prog_quants;
        self.quality = quality;
        self.pass = self.pass.saturating_add(1);
        Ok(())
    }

    /// Reconstruct the tile to spatial domain and write RGBA pixels.
    ///
    /// Applies inverse DWT to each component, then YCbCr-to-RGB color
    /// conversion. The pixel buffer receives 64x64 RGBA pixels (16384 bytes).
    ///
    /// # Panics
    ///
    /// Panics if `pixels` has fewer than 64 * 64 * 4 = 16384 bytes.
    #[expect(clippy::similar_names, reason = "y/cb/cr are standard YCbCr component names")]
    pub fn reconstruct_to_rgba(&self, pixels: &mut [u8]) {
        assert!(pixels.len() >= 64 * 64 * 4, "pixel buffer too small");

        // Copy coefficients to scratch buffers for in-place DWT
        let mut y_buf = self.coefficients[0];
        let mut cb_buf = self.coefficients[1];
        let mut cr_buf = self.coefficients[2];
        let mut temp = [0i16; COEFFICIENTS_PER_COMPONENT];

        // Inverse DWT
        if self.use_reduce_extrapolate {
            crate::dwt_extrapolate::decode(&mut y_buf, &mut temp);
            crate::dwt_extrapolate::decode(&mut cb_buf, &mut temp);
            crate::dwt_extrapolate::decode(&mut cr_buf, &mut temp);
        } else {
            let mut dwt_temp = [0i16; COEFFICIENTS_PER_COMPONENT];
            crate::dwt::decode(&mut y_buf, &mut dwt_temp);
            crate::dwt::decode(&mut cb_buf, &mut dwt_temp);
            crate::dwt::decode(&mut cr_buf, &mut dwt_temp);
        }

        // Escale : conversion de FreeRDP (general_yCbCrToRGB_16s8u_P3AC4R : virgule fixe 11.5,
        // constantes ycbcr_constants[16]), calculée sur 64 bits : aucune valeur ne déborde, plus
        // besoin de borner les coefficients avant la conversion
        for (i, px) in pixels[..64 * 64 * 4].chunks_exact_mut(4).enumerate() {
            let [r, g, b] = ycbcr_to_rgb(y_buf[i], cb_buf[i], cr_buf[i]);
            px.copy_from_slice(&[r, g, b, 0xFF]);
        }
    }
}

/// Escale : un pixel YCbCr 11.5 en RVB, comme FreeRDP (`general_yCbCrToRGB_16s8u_P3AC4R`).
#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "valeur bornée à 0..=255 avant la conversion"
)]
pub fn ycbcr_to_rgb(y: i16, cb: i16, cr: i16) -> [u8; 3] {
    const DIVISOR: u32 = 16;
    let y = (i64::from(y) + 4096) << DIVISOR;
    let (cb, cr) = (i64::from(cb), i64::from(cr));
    let clip = |v: i64| ((v >> DIVISOR) >> 5).clamp(0, 255) as u8;
    [
        clip(cr * 91916 + y),
        clip(y - cb * 22527 - cr * 46819),
        clip(cb * 115992 + y),
    ]
}

impl Default for TileState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Surface tile grid
// ---------------------------------------------------------------------------

/// Grid of progressive tiles for a single surface.
///
/// Manages tile state for a surface identified by its codec context ID.
/// Tiles are lazily allocated on first access to avoid upfront memory
/// cost for surfaces that only partially receive progressive updates.
pub struct SurfaceTiles {
    /// Width of the surface in tiles (ceildiv of pixel width by 64).
    pub tiles_wide: u16,
    /// Height of the surface in tiles.
    pub tiles_high: u16,
    /// Whether the associated context uses reduce-extrapolate DWT.
    pub use_reduce_extrapolate: bool,
    /// Tile storage, indexed by `y_idx * tiles_wide + x_idx`.
    /// `None` entries haven't received any progressive data yet.
    pub tiles: Vec<Option<Box<TileState>>>,
}

impl SurfaceTiles {
    /// Create a new tile grid for the given surface dimensions.
    ///
    /// Returns [`ProgressiveDecodeError::SurfaceTooLarge`] if either axis
    /// exceeds [`MAX_SURFACE_DIM`]. The check rejects only inputs that exceed
    /// the MS-RDPEGFX 2.2.2.14 normative ceiling (32766 px), so every
    /// spec-conformant surface is accepted.
    pub fn new(
        width_pixels: u16,
        height_pixels: u16,
        use_reduce_extrapolate: bool,
    ) -> Result<Self, ProgressiveDecodeError> {
        if width_pixels > MAX_SURFACE_DIM || height_pixels > MAX_SURFACE_DIM {
            return Err(ProgressiveDecodeError::SurfaceTooLarge {
                width: width_pixels,
                height: height_pixels,
            });
        }

        // Escale : grille de FreeRDP, (largeur + (64 - largeur % 64)) / 64 : une colonne / ligne de
        // plus quand la taille est multiple de 64 (tuiles de bord tolérées, rognées à l'affichage)
        let tiles_wide = grid_tiles(width_pixels);
        let tiles_high = grid_tiles(height_pixels);
        let count = usize::from(tiles_wide) * usize::from(tiles_high);

        Ok(Self {
            tiles_wide,
            tiles_high,
            use_reduce_extrapolate,
            tiles: core::iter::repeat_with(|| None).take(count).collect(),
        })
    }

    /// Get or create the tile at the given grid position.
    ///
    /// Returns `None` if the coordinates are out of bounds.
    pub fn get_or_create(&mut self, x_idx: u16, y_idx: u16) -> Option<&mut TileState> {
        let idx = self.tile_index(x_idx, y_idx)?;
        let tile = self.tiles[idx].get_or_insert_with(|| {
            let mut t = Box::new(TileState::new());
            t.use_reduce_extrapolate = self.use_reduce_extrapolate;
            t
        });
        Some(tile)
    }

    /// Get the tile at the given grid position, if it exists.
    pub fn get(&self, x_idx: u16, y_idx: u16) -> Option<&TileState> {
        let idx = self.tile_index(x_idx, y_idx)?;
        self.tiles[idx].as_deref()
    }

    /// Reset all tiles (e.g., on context reset or surface resize).
    pub fn reset(&mut self) {
        for tile in &mut self.tiles {
            *tile = None;
        }
    }

    fn tile_index(&self, x_idx: u16, y_idx: u16) -> Option<usize> {
        if x_idx >= self.tiles_wide || y_idx >= self.tiles_high {
            return None;
        }
        Some(usize::from(y_idx) * usize::from(self.tiles_wide) + usize::from(x_idx))
    }
}

// ---------------------------------------------------------------------------
// Progressive decoder (EGFX integration)
// ---------------------------------------------------------------------------

/// Escale : nombre de tuiles d'un côté de la grille (formule de FreeRDP).
fn grid_tiles(pixels: u16) -> u16 {
    pixels / 64 + 1
}

/// Decoded tile pixel data for compositing onto a surface.
pub struct DecodedTile {
    /// Tile grid X coordinate (tile column).
    pub x_idx: u16,
    /// Tile grid Y coordinate (tile row).
    pub y_idx: u16,
    /// RGBA pixel data (64x64 = 16384 bytes).
    pub pixels: Vec<u8>,
}

/// Per-axis cap on surface dimensions, in pixels.
///
/// Per MS-RDPEGFX 2.2.2.14 RDPGFX_RESET_GRAPHICS_PDU, the normative maximum
/// allowed width and height are 32766 pixels. We round up to 32768 so that
/// the cap accepts every spec-conformant surface while bounding the
/// per-surface tile-grid allocation: at the cap the backing
/// `Vec<Option<Box<TileState>>>` is 512 * 512 = 262144 slots * 8 bytes per
/// slot = 2 MiB of pointer storage per surface before any tile is populated.
pub const MAX_SURFACE_DIM: u16 = 32768;

/// Error type for progressive decoding operations.
#[derive(Debug)]
pub enum ProgressiveDecodeError {
    /// PDU parsing failed.
    Pdu(ironrdp_core::DecodeError),
    /// RLGR decode failed within a tile.
    Rlgr(RlgrError),
    /// The progressive stream is missing a required block.
    MissingBlock(&'static str),
    /// Tile coordinates are out of bounds for the surface.
    TileOutOfBounds { x_idx: u16, y_idx: u16 },
    /// Region references a quant index beyond the table.
    InvalidQuantIndex { index: usize, table_len: usize },
    /// Surface dimensions exceed [`MAX_SURFACE_DIM`] per axis.
    SurfaceTooLarge { width: u16, height: u16 },
    /// Escale : passe d'amélioration d'une tuile jamais reçue en première passe.
    UpgradeWithoutFirstPass { x_idx: u16, y_idx: u16 },
    /// Escale : passe d'amélioration incohérente avec la précédente.
    Upgrade { x_idx: u16, y_idx: u16, error: UpgradeError },
}

impl core::fmt::Display for ProgressiveDecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Pdu(e) => write!(f, "progressive PDU decode: {e}"),
            Self::Rlgr(e) => write!(f, "progressive RLGR decode: {e}"),
            Self::MissingBlock(name) => write!(f, "progressive stream missing {name} block"),
            Self::TileOutOfBounds { x_idx, y_idx } => {
                write!(f, "tile ({x_idx}, {y_idx}) out of surface bounds")
            }
            Self::InvalidQuantIndex { index, table_len } => {
                write!(f, "quant index {index} exceeds table length {table_len}")
            }
            Self::UpgradeWithoutFirstPass { x_idx, y_idx } => {
                write!(f, "amélioration de la tuile ({x_idx}, {y_idx}) sans première passe")
            }
            Self::Upgrade { x_idx, y_idx, error } => write!(f, "amélioration de la tuile ({x_idx}, {y_idx}) : {error}"),
            Self::SurfaceTooLarge { width, height } => {
                write!(
                    f,
                    "surface dimensions {width}x{height} exceed per-axis cap of {MAX_SURFACE_DIM} \
                     (MS-RDPEGFX 2.2.2.14 normative ceiling: 32766)"
                )
            }
        }
    }
}

impl From<ironrdp_core::DecodeError> for ProgressiveDecodeError {
    fn from(e: ironrdp_core::DecodeError) -> Self {
        Self::Pdu(e)
    }
}

impl From<RlgrError> for ProgressiveDecodeError {
    fn from(e: RlgrError) -> Self {
        Self::Rlgr(e)
    }
}

/// Per-context progressive state, identified by codec_context_id.
struct ProgressiveContext {
    surface: SurfaceTiles,
}

/// High-level progressive bitmap decoder for EGFX WireToSurface2 processing.
///
/// Maintains per-context tile state across frames, keyed by `codec_context_id`.
/// Feed it progressive bitmap data from `WireToSurface2Pdu.bitmap_data` and
/// get back decoded RGBA tiles for compositing.
///
/// # Usage
///
/// ```ignore
/// let mut decoder = ProgressiveDecoder::new();
///
/// // On receiving WireToSurface2Pdu:
/// let tiles = decoder.decode_bitmap(
///     pdu.codec_context_id,
///     surface_width, surface_height,
///     &pdu.bitmap_data,
/// )?;
///
/// for tile in &tiles {
///     blit_tile(surface, tile.x_idx, tile.y_idx, &tile.pixels);
/// }
/// ```
pub struct ProgressiveDecoder {
    contexts: BTreeMap<u32, ProgressiveContext>,
    /// Escale : dernier mode DWT annoncé par un bloc CONTEXT.
    last_reduce_extrapolate: Option<bool>,
}

impl ProgressiveDecoder {
    /// Create a new progressive decoder with no context state.
    pub fn new() -> Self {
        Self {
            contexts: BTreeMap::new(),
            last_reduce_extrapolate: None,
        }
    }

    /// Decode a progressive bitmap stream from WireToSurface2Pdu.
    ///
    /// Parses the progressive block stream, updates per-tile state, and
    /// returns RGBA pixel data for each tile that was updated.
    ///
    /// # Arguments
    /// - `codec_context_id`: context ID from the WireToSurface2Pdu
    /// - `surface_width`: surface width in pixels (for tile grid sizing)
    /// - `surface_height`: surface height in pixels
    /// - `bitmap_data`: raw progressive block stream from the PDU
    pub fn decode_bitmap(
        &mut self,
        codec_context_id: u32,
        surface_width: u16,
        surface_height: u16,
        bitmap_data: &[u8],
    ) -> Result<Vec<DecodedTile>, ProgressiveDecodeError> {
        use ironrdp_pdu::codecs::rfx::progressive::{ProgressiveBlock, decode_progressive_stream};

        let blocks = decode_progressive_stream(bitmap_data)?;

        // Extract the band-layout flag from the CONTEXT block when present.
        // Per MS-RDPEGFX 2.2.4.2 the SYNC + CONTEXT blocks establish a codec
        // context once (keyed by `codec_context_id`) and are not required to be
        // repeated on subsequent frames that reference the same context.
        // Real-world servers (xrdp, GNOME Remote Desktop) omit the CONTEXT
        // block on every frame after the first one that established the
        // context. The strict requirement rejected each of those frames with
        // `MissingBlock("CONTEXT")`, freezing the image on the coarse first
        // pass.
        //
        // Fall back to the value stored when the context was first created.
        // Only error when neither source is available, i.e. the very first
        // frame for a context arrived without a CONTEXT block.
        // Escale : le mode de DWT est donné par chaque bloc REGION (RFX_DWT_REDUCE_EXTRAPOLATE,
        // MS-RDPEGFX 2.2.4.2.1.5), comme le lit FreeRDP ; l'indicateur 0x01 du bloc CONTEXT est
        // RFX_SUBBAND_DIFFING. Windows met les deux à 1, FreeRDP / xrdp un CONTEXT à 0 : lire le
        // CONTEXT décodait leurs tuiles avec la mauvaise DWT. Le bloc CONTEXT n'est plus requis.
        let use_reduce_extrapolate = blocks
            .iter()
            .find_map(|block| match block {
                ProgressiveBlock::Region(r) => Some(r.uses_reduce_extrapolate()),
                _ => None,
            })
            .or(self.last_reduce_extrapolate)
            .unwrap_or(true);
        self.last_reduce_extrapolate = Some(use_reduce_extrapolate);

        // Get or create the context for this codec_context_id
        let context = match self.contexts.entry(codec_context_id) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => {
                let surface = SurfaceTiles::new(surface_width, surface_height, use_reduce_extrapolate)?;
                e.insert(ProgressiveContext { surface })
            }
        };

        // If surface dimensions changed, reallocate
        let expected_wide = grid_tiles(surface_width);
        let expected_high = grid_tiles(surface_height);
        if context.surface.tiles_wide != expected_wide || context.surface.tiles_high != expected_high {
            context.surface = SurfaceTiles::new(surface_width, surface_height, use_reduce_extrapolate)?;
        }
        context.surface.use_reduce_extrapolate = use_reduce_extrapolate;

        let mut decoded_tiles = Vec::new();

        // Process REGION blocks (the main content)
        for block in &blocks {
            let region = match block {
                ProgressiveBlock::Region(r) => r,
                _ => continue,
            };

            let quant_vals = &region.quant_vals;
            let prog_quant_vals = &region.quant_prog_vals;
            let use_reduce_extrapolate = region.uses_reduce_extrapolate();

            for tile_block in &region.tiles {
                // Escale : une tuile illisible ne fait pas perdre les autres
                match decode_tile_block(
                    &mut context.surface,
                    tile_block,
                    quant_vals,
                    prog_quant_vals,
                    use_reduce_extrapolate,
                ) {
                    Ok(tiles) => decoded_tiles.extend(tiles),
                    Err(e) => {
                        if std::env::var_os("ESCALE_GFX_DEBUG").is_some() {
                            eprintln!("gfx : RemoteFX Progressive, contexte {codec_context_id} : tuile ignorée : {e}");
                        }
                    }
                }
            }
        }

        Ok(decoded_tiles)
    }

    /// Delete a codec context, freeing its tile state.
    ///
    /// Called when the server sends RDPGFX_DELETE_ENCODING_CONTEXT.
    pub fn delete_context(&mut self, codec_context_id: u32) {
        self.contexts.remove(&codec_context_id);
    }

    /// Reset all contexts (e.g., on EGFX channel reset).
    pub fn reset(&mut self) {
        self.contexts.clear();
        self.last_reduce_extrapolate = None;
    }
}

/// RFX_TILE_DIFFERENCE : coefficients relatifs à ceux de la tuile précédente.
const TILE_DIFFERENCE: u8 = 0x01;

/// Escale : quantification progressive d'un niveau de qualité ; 0xFF = pleine qualité.
fn prog_quant_for(
    prog_quant_vals: &[ironrdp_pdu::codecs::rfx::progressive::ProgressiveCodecQuant],
    quality: u8,
) -> Result<[ComponentCodecQuant; 3], ProgressiveDecodeError> {
    if quality == 0xFF {
        return Ok([ComponentCodecQuant::LOSSLESS; 3]);
    }
    let pq = prog_quant_vals
        .get(usize::from(quality))
        .ok_or(ProgressiveDecodeError::InvalidQuantIndex {
            index: usize::from(quality),
            table_len: prog_quant_vals.len(),
        })?;
    Ok([pq.y_quant, pq.cb_quant, pq.cr_quant])
}

#[expect(
    clippy::similar_names,
    reason = "q_y/q_cb/q_cr are standard component quant index names"
)]
fn decode_tile_block(
    surface: &mut SurfaceTiles,
    tile_block: &ironrdp_pdu::codecs::rfx::progressive::ProgressiveTile<'_>,
    quant_vals: &[ComponentCodecQuant],
    prog_quant_vals: &[ironrdp_pdu::codecs::rfx::progressive::ProgressiveCodecQuant],
    use_reduce_extrapolate: bool,
) -> Result<Vec<DecodedTile>, ProgressiveDecodeError> {
    use ironrdp_pdu::codecs::rfx::progressive::ProgressiveTile;

    match tile_block {
        ProgressiveTile::Simple(tile) => {
            let x_idx = tile.x_idx;
            let y_idx = tile.y_idx;

            let tile_state = surface
                .get_or_create(x_idx, y_idx)
                .ok_or(ProgressiveDecodeError::TileOutOfBounds { x_idx, y_idx })?;

            let q_y = usize::from(tile.quant_idx_y);
            let q_cb = usize::from(tile.quant_idx_cb);
            let q_cr = usize::from(tile.quant_idx_cr);

            if q_y >= quant_vals.len() || q_cb >= quant_vals.len() || q_cr >= quant_vals.len() {
                return Err(ProgressiveDecodeError::InvalidQuantIndex {
                    index: q_y.max(q_cb).max(q_cr),
                    table_len: quant_vals.len(),
                });
            }

            // TILE_SIMPLE uses lossless progressive quant (no progressive refinement)
            let prog = ComponentCodecQuant::LOSSLESS;

            tile_state.decode_first_diff(
                [tile.y_data, tile.cb_data, tile.cr_data],
                [&quant_vals[q_y], &quant_vals[q_cb], &quant_vals[q_cr]],
                [prog, prog, prog],
                [tile.quant_idx_y, tile.quant_idx_cb, tile.quant_idx_cr],
                0xFF, // full quality
                use_reduce_extrapolate,
                tile.flags & TILE_DIFFERENCE != 0,
            )?;

            let mut pixels = vec![0u8; 64 * 64 * 4];
            tile_state.reconstruct_to_rgba(&mut pixels);

            Ok(vec![DecodedTile { x_idx, y_idx, pixels }])
        }

        ProgressiveTile::First(tile) => {
            let x_idx = tile.x_idx;
            let y_idx = tile.y_idx;

            let tile_state = surface
                .get_or_create(x_idx, y_idx)
                .ok_or(ProgressiveDecodeError::TileOutOfBounds { x_idx, y_idx })?;

            let q_y = usize::from(tile.quant_idx_y);
            let q_cb = usize::from(tile.quant_idx_cb);
            let q_cr = usize::from(tile.quant_idx_cr);

            if q_y >= quant_vals.len() || q_cb >= quant_vals.len() || q_cr >= quant_vals.len() {
                return Err(ProgressiveDecodeError::InvalidQuantIndex {
                    index: q_y.max(q_cb).max(q_cr),
                    table_len: quant_vals.len(),
                });
            }

            let prog = prog_quant_for(prog_quant_vals, tile.quality)?;

            tile_state.decode_first_diff(
                [tile.y_data, tile.cb_data, tile.cr_data],
                [&quant_vals[q_y], &quant_vals[q_cb], &quant_vals[q_cr]],
                prog,
                [tile.quant_idx_y, tile.quant_idx_cb, tile.quant_idx_cr],
                tile.quality,
                use_reduce_extrapolate,
                tile.flags & TILE_DIFFERENCE != 0,
            )?;

            let mut pixels = vec![0u8; 64 * 64 * 4];
            tile_state.reconstruct_to_rgba(&mut pixels);

            Ok(vec![DecodedTile { x_idx, y_idx, pixels }])
        }

        ProgressiveTile::Upgrade(tile) => {
            let x_idx = tile.x_idx;
            let y_idx = tile.y_idx;

            let tile_state = surface
                .get_or_create(x_idx, y_idx)
                .ok_or(ProgressiveDecodeError::TileOutOfBounds { x_idx, y_idx })?;

            // If this tile hasn't had a first pass, skip the upgrade
            if tile_state.pass == 0 {
                return Err(ProgressiveDecodeError::UpgradeWithoutFirstPass { x_idx, y_idx });
            }

            let prog = prog_quant_for(prog_quant_vals, tile.quality)?;
            let q_y = usize::from(tile.quant_idx_y);
            let q_cb = usize::from(tile.quant_idx_cb);
            let q_cr = usize::from(tile.quant_idx_cr);
            if q_y >= quant_vals.len() || q_cb >= quant_vals.len() || q_cr >= quant_vals.len() {
                return Err(ProgressiveDecodeError::InvalidQuantIndex {
                    index: q_y.max(q_cb).max(q_cr),
                    table_len: quant_vals.len(),
                });
            }

            tile_state.use_reduce_extrapolate = use_reduce_extrapolate;
            tile_state.decode_upgrade(
                [tile.y_srl_data, tile.cb_srl_data, tile.cr_srl_data],
                [tile.y_raw_data, tile.cb_raw_data, tile.cr_raw_data],
                [&quant_vals[q_y], &quant_vals[q_cb], &quant_vals[q_cr]],
                prog,
                tile.quality,
            )
            .map_err(|e| ProgressiveDecodeError::Upgrade { x_idx, y_idx, error: e })?;

            let mut pixels = vec![0u8; 64 * 64 * 4];
            tile_state.reconstruct_to_rgba(&mut pixels);

            Ok(vec![DecodedTile { x_idx, y_idx, pixels }])
        }
    }
}

impl Default for ProgressiveDecoder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::as_conversions, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
mod tests {
    use super::*;

    #[test]
    fn surface_tiles_rejects_over_cap_dimensions() {
        // At-cap accepted on both axes
        assert!(SurfaceTiles::new(MAX_SURFACE_DIM, MAX_SURFACE_DIM, false).is_ok());

        // One axis over the cap is rejected with SurfaceTooLarge carrying both inputs
        let over_w = MAX_SURFACE_DIM.checked_add(1).unwrap();
        match SurfaceTiles::new(over_w, 1024, false) {
            Err(ProgressiveDecodeError::SurfaceTooLarge { width, height }) => {
                assert_eq!(width, over_w);
                assert_eq!(height, 1024);
            }
            Err(other) => panic!("expected SurfaceTooLarge, got Err({other})"),
            Ok(_) => panic!("expected SurfaceTooLarge, got Ok"),
        }

        match SurfaceTiles::new(1024, over_w, false) {
            Err(ProgressiveDecodeError::SurfaceTooLarge { width, height }) => {
                assert_eq!(width, 1024);
                assert_eq!(height, over_w);
            }
            Err(other) => panic!("expected SurfaceTooLarge, got Err({other})"),
            Ok(_) => panic!("expected SurfaceTooLarge, got Ok"),
        }
    }

    #[test]
    fn standard_band_layout_totals_4096() {
        let bands = standard_band_layout();
        let total: usize = bands.iter().map(|b| b.count()).sum();
        assert_eq!(total, 4096);
    }

    #[test]
    fn standard_band_offsets() {
        let bands = standard_band_layout();
        assert_eq!(bands[0].offset, 0);
        assert_eq!(bands[1].offset, 1024);
        assert_eq!(bands[2].offset, 2048);
        assert_eq!(bands[3].offset, 3072);
        assert_eq!(bands[4].offset, 3328);
        assert_eq!(bands[5].offset, 3584);
        assert_eq!(bands[6].offset, 3840);
        assert_eq!(bands[7].offset, 3904);
        assert_eq!(bands[8].offset, 3968);
        assert_eq!(bands[9].offset, 4032);
    }

    #[test]
    fn sign_capture_tri_state() {
        let coefficients = [10i16, -5, 0, 100, -1, 0];
        let mut sign = [0i8; 6];
        capture_sign(&coefficients, &mut sign);
        assert_eq!(sign, [1, -1, 0, 1, -1, 0]);
    }

    #[test]
    fn progressive_dequantize_ll3_shift() {
        // LL3 is band index 9, at offset 4032 for standard layout
        let mut coefficients = vec![0i16; 4096];
        coefficients[4032] = 5;
        coefficients[4033] = -3;

        let prog_quant = ComponentCodecQuant {
            ll3: 2,
            hl3: 0,
            lh3: 0,
            hh3: 0,
            hl2: 0,
            lh2: 0,
            hh2: 0,
            hl1: 0,
            lh1: 0,
            hh1: 0,
        };

        progressive_dequantize(&mut coefficients, &prog_quant, false);

        // LL3 uses floor shift: 5 << 2 = 20, -3 << 2 = -12
        assert_eq!(coefficients[4032], 20);
        assert_eq!(coefficients[4033], -12);
    }

    #[test]
    fn progressive_dequantize_non_ll3_preserves_sign() {
        // HL1 is band index 0, at offset 0 for standard layout
        let mut coefficients = vec![0i16; 4096];
        coefficients[0] = 5;
        coefficients[1] = -5;

        let prog_quant = ComponentCodecQuant {
            ll3: 0,
            hl3: 0,
            lh3: 0,
            hh3: 0,
            hl2: 0,
            lh2: 0,
            hh2: 0,
            hl1: 2,
            lh1: 0,
            hh1: 0,
        };

        progressive_dequantize(&mut coefficients, &prog_quant, false);

        // Non-LL3: shift absolute value, preserve sign
        assert_eq!(coefficients[0], 20); // 5 << 2
        assert_eq!(coefficients[1], -20); // -(5 << 2)
    }

    #[test]
    fn progressive_quantize_round_trip() {
        let mut coefficients = vec![0i16; 4096];
        for (i, c) in coefficients.iter_mut().enumerate() {
            *c = (i as i16).wrapping_mul(7);
        }
        let original = coefficients.clone();

        let prog_quant = ComponentCodecQuant {
            ll3: 2,
            hl3: 3,
            lh3: 3,
            hh3: 4,
            hl2: 3,
            lh2: 3,
            hh2: 4,
            hl1: 2,
            lh1: 2,
            hh1: 3,
        };

        progressive_quantize(&mut coefficients, &prog_quant, false);
        progressive_dequantize(&mut coefficients, &prog_quant, false);

        // After quantize->dequantize, values lose precision from truncation
        // but should be in the right ballpark
        for (i, (&a, &b)) in coefficients.iter().zip(original.iter()).enumerate() {
            let err = (i32::from(a) - i32::from(b)).unsigned_abs();
            // Max error bounded by 2^(bit_pos)
            assert!(err < 32, "index {i}: error {err} too large");
        }
    }

    #[test]
    fn raw_bit_reader_basic() {
        let data = [0b10110000, 0b01010000];
        let mut reader = RawBitReader::new(&data);
        assert_eq!(reader.read_bits(4), 0b1011);
        assert_eq!(reader.read_bits(4), 0b0000);
        assert_eq!(reader.read_bits(4), 0b0101);
    }

    #[test]
    fn clamp_i16_limits() {
        assert_eq!(clamp_i16(40000), i16::MAX);
        assert_eq!(clamp_i16(-40000), i16::MIN);
        assert_eq!(clamp_i16(100), 100);
        assert_eq!(clamp_i16(-100), -100);
    }

    #[test]
    fn ll3_offsets_correct() {
        assert_eq!(ll3_offset(false), 4032);
        assert_eq!(ll3_offset(true), 4015);
    }

    /// Escale : LL3 toujours lu en brut (même nul), HL1 de signe nul lu en SRL, états SRL / RAW
    /// partagés entre bandes (FreeRDP progressive_rfx_upgrade_component).
    #[test]
    fn upgrade_pass_matches_freerdp() {
        let mut coefficients = vec![0i16; 4096];
        let mut sign = vec![SIGN_ZERO; 4096];
        let mut prev = [6u8; NUM_BANDS];
        prev[0] = 8; // HL1 : 2 bits
        prev[9] = 7; // LL3 : 1 bit
        let curr = [6u8; NUM_BANDS];
        // SRL (kp 8, k 1) : '1' + '0' (aucun zéro), signe '0', unaire '01' -> 2 ; puis zéros
        let srl_data = [0b1000_1000];
        // RAW : 81 bits de LL3, le premier à 1
        let raw_data = [0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let extrapolate = true;
        decode_upgrade_pass(&srl_data, &raw_data, &prev, &curr, extrapolate, &mut coefficients, &mut sign).unwrap();
        assert_eq!(coefficients[0], 2 << 5);
        assert_eq!(sign[0], SIGN_POSITIVE);
        assert!(coefficients[1..1023].iter().all(|&v| v == 0));
        assert_eq!(coefficients[4015], 1 << 5);
        assert!(coefficients[4016..].iter().all(|&v| v == 0));
        // position de bit en hausse : refusée
        assert!(decode_upgrade_pass(&[], &[], &curr, &prev, extrapolate, &mut coefficients, &mut sign).is_err());
    }

    #[test]
    fn tile_state_default_is_zeroed() {
        let tile = TileState::new();
        assert_eq!(tile.pass, 0);
        assert_eq!(tile.quality, 0);
        assert!(!tile.use_reduce_extrapolate);
        assert!(tile.coefficients[0].iter().all(|&v| v == 0));
        assert!(tile.sign[0].iter().all(|&v| v == 0));
    }

    #[test]
    fn surface_tiles_dimensions() {
        let surface = SurfaceTiles::new(1920, 1080, true).unwrap();
        assert_eq!(surface.tiles_wide, 31); // grille de FreeRDP : colonne de plus si multiple de 64
        assert_eq!(surface.tiles_high, 17);
        assert!(surface.use_reduce_extrapolate);
    }

    #[test]
    fn surface_tiles_exact_multiple() {
        // grille de FreeRDP : (taille + (64 - taille % 64)) / 64
        let surface = SurfaceTiles::new(1280, 768, false).unwrap();
        assert_eq!(surface.tiles_wide, 21);
        assert_eq!(surface.tiles_high, 13);
    }

    #[test]
    fn surface_tiles_lazy_allocation() {
        let mut surface = SurfaceTiles::new(128, 128, false).unwrap();
        // No tiles allocated yet
        assert!(surface.get(0, 0).is_none());

        // Access creates tile
        let tile = surface.get_or_create(0, 0).unwrap();
        assert_eq!(tile.pass, 0);
        assert!(!tile.use_reduce_extrapolate);

        // Now it exists
        assert!(surface.get(0, 0).is_some());

        // Out of bounds returns None (grille de FreeRDP : 128 px -> 3 tuiles)
        assert!(surface.get_or_create(3, 3).is_none());
    }

    #[test]
    fn surface_tiles_reset() {
        let mut surface = SurfaceTiles::new(128, 128, false).unwrap();
        surface.get_or_create(0, 0);
        assert!(surface.get(0, 0).is_some());

        surface.reset();
        assert!(surface.get(0, 0).is_none());
    }

    #[test]
    fn decoder_new_is_empty() {
        let decoder = ProgressiveDecoder::new();
        assert!(decoder.contexts.is_empty());
    }

    #[test]
    fn decoder_delete_nonexistent_context() {
        let mut decoder = ProgressiveDecoder::new();
        // Should not panic on non-existent context
        decoder.delete_context(42);
    }

    #[test]
    fn decoder_reset_clears_contexts() {
        let mut decoder = ProgressiveDecoder::new();

        // Decode a minimal valid stream to create a context
        use ironrdp_pdu::codecs::rfx::RfxRectangle;
        use ironrdp_pdu::codecs::rfx::progressive::{
            ProgressiveBlock, ProgressiveContextPdu, ProgressiveFrameBeginPdu, ProgressiveFrameEndPdu,
            ProgressiveRegion, ProgressiveSyncPdu, encode_progressive_stream,
        };

        let region = ProgressiveRegion {
            tile_size: 0x40,
            rects: vec![RfxRectangle {
                x: 0,
                y: 0,
                width: 64,
                height: 64,
            }],
            quant_vals: vec![],
            quant_prog_vals: vec![],
            flags: 0,
            tiles: vec![],
        };

        let blocks = vec![
            ProgressiveBlock::Sync(ProgressiveSyncPdu),
            ProgressiveBlock::Context(ProgressiveContextPdu {
                context_id: 0,
                tile_size: 0x0040,
                flags: 0,
            }),
            ProgressiveBlock::FrameBegin(ProgressiveFrameBeginPdu {
                frame_index: 0,
                region_count: 1,
            }),
            ProgressiveBlock::Region(region),
            ProgressiveBlock::FrameEnd(ProgressiveFrameEndPdu),
        ];

        let encoded = encode_progressive_stream(&blocks).unwrap();
        let result = decoder.decode_bitmap(1, 640, 480, &encoded);
        assert!(result.is_ok());
        assert_eq!(decoder.contexts.len(), 1);

        decoder.reset();
        assert!(decoder.contexts.is_empty());
    }

    #[test]
    fn decoder_error_display() {
        let e = ProgressiveDecodeError::MissingBlock("SYNC");
        assert!(e.to_string().contains("SYNC"));

        let e = ProgressiveDecodeError::TileOutOfBounds { x_idx: 5, y_idx: 10 };
        assert!(e.to_string().contains("5"));
        assert!(e.to_string().contains("10"));

        let e = ProgressiveDecodeError::InvalidQuantIndex { index: 3, table_len: 2 };
        assert!(e.to_string().contains("3"));
    }

    #[test]
    fn dequantize_component_ccq_shifts_correctly() {
        let mut coefficients = vec![0i16; 4096];
        coefficients[0] = 10; // HL1 band (index 0)
        coefficients[4032] = 5; // LL3 band (index 9, standard layout)

        let quant = ComponentCodecQuant {
            ll3: 3,
            hl3: 0,
            lh3: 0,
            hh3: 0,
            hl2: 0,
            lh2: 0,
            hh2: 0,
            hl1: 4,
            lh1: 0,
            hh1: 0,
        };

        dequantize_component_ccq(&mut coefficients, &quant, false);

        // HL1: shift left by (4 - 1) = 3 -> 10 << 3 = 80
        assert_eq!(coefficients[0], 80);
        // LL3: shift left by (3 - 1) = 2 -> 5 << 2 = 20
        assert_eq!(coefficients[4032], 20);
    }

    // --- B10: Server encode pipeline tests ---

    #[test]
    fn rgba_to_ycbcr_pure_white() {
        let pixels = vec![255u8; 64 * 64 * 4];
        let mut y = vec![0i16; 4096];
        let mut cb = vec![0i16; 4096];
        let mut cr = vec![0i16; 4096];

        rgba_to_ycbcr(&pixels, &mut y, &mut cb, &mut cr);

        // Pure white: R=G=B=255
        // Y = (19595*255 + 38470*255 + 7471*255 + 32768) >> 16 - 128
        //   = (65536*255 + 32768) >> 16 - 128 = 255 - 128 = 127
        // Cb and Cr should be ~0 (achromatic)
        assert!((y[0] - 127).abs() <= 1, "Y for white: got {}", y[0]);
        assert!(cb[0].abs() <= 1, "Cb for white: got {}", cb[0]);
        assert!(cr[0].abs() <= 1, "Cr for white: got {}", cr[0]);
    }

    #[test]
    fn rgba_to_ycbcr_pure_black() {
        let pixels = vec![0u8; 64 * 64 * 4];
        let mut y = vec![0i16; 4096];
        let mut cb = vec![0i16; 4096];
        let mut cr = vec![0i16; 4096];

        rgba_to_ycbcr(&pixels, &mut y, &mut cb, &mut cr);

        // Pure black: Y = -128, Cb = 0, Cr = 0
        assert_eq!(y[0], -128);
        assert_eq!(cb[0], 0);
        assert_eq!(cr[0], 0);
    }

    #[test]
    fn quantize_ccq_right_shifts() {
        let mut coefficients = [0i16; 4096];
        coefficients[0] = 80; // HL1 band
        coefficients[4032] = 20; // LL3 band

        let quant = ComponentCodecQuant {
            ll3: 3,
            hl3: 0,
            lh3: 0,
            hh3: 0,
            hl2: 0,
            lh2: 0,
            hh2: 0,
            hl1: 4,
            lh1: 0,
            hh1: 0,
        };

        quantize_component_ccq(&mut coefficients, &quant, false);

        // HL1: 80 >> (4 - 1) = 80 >> 3 = 10
        assert_eq!(coefficients[0], 10);
        // LL3: 20 >> (3 - 1) = 20 >> 2 = 5
        assert_eq!(coefficients[4032], 5);
    }

    #[test]
    fn quantize_ccq_negative_truncates_toward_zero() {
        let mut coefficients = [0i16; 4096];
        coefficients[0] = -80; // HL1 band, negative

        let quant = ComponentCodecQuant {
            ll3: 0,
            hl3: 0,
            lh3: 0,
            hh3: 0,
            hl2: 0,
            lh2: 0,
            hh2: 0,
            hl1: 4,
            lh1: 0,
            hh1: 0,
        };

        quantize_component_ccq(&mut coefficients, &quant, false);

        // -80 truncated toward zero: -(80 >> 3) = -10
        assert_eq!(coefficients[0], -10);
    }

    #[test]
    fn raw_bit_writer_single_byte() {
        let mut w = RawBitWriter::new();
        w.write_bits(0xA5, 8);
        assert_eq!(w.finish(), vec![0xA5]);
    }

    #[test]
    fn raw_bit_writer_partial_byte_padded() {
        let mut w = RawBitWriter::new();
        w.write_bits(0b101, 3);
        // 3 bits: 101, padded to 10100000 = 0xA0
        assert_eq!(w.finish(), vec![0xA0]);
    }

    #[test]
    fn raw_bit_writer_multi_byte() {
        let mut w = RawBitWriter::new();
        w.write_bits(0xFF, 8);
        w.write_bits(0b1010, 4);
        // First byte: 0xFF, second partial: 1010_0000 = 0xA0
        assert_eq!(w.finish(), vec![0xFF, 0xA0]);
    }

    #[test]
    fn encode_first_pass_produces_output() {
        // Flat tile: all same value, should compress well
        let mut coefficients = [100i16; 4096];
        let mut output = vec![0u8; 8192];

        let base_quant = ComponentCodecQuant::LOSSLESS;
        let prog_quant = ComponentCodecQuant::LOSSLESS;

        let result = encode_first_pass(&mut coefficients, &mut output, &base_quant, &prog_quant, false);

        assert!(result.is_ok(), "RLGR encode failed: {:?}", result.err());
        let bytes_written = result.unwrap();
        assert!(bytes_written > 0, "expected non-zero encoded output");
        assert!(bytes_written < 8192, "flat tile should compress");
    }

    #[test]
    fn encode_first_pass_reduce_extrapolate() {
        let mut coefficients = [50i16; 4096];
        let mut output = vec![0u8; 8192];

        let base_quant = ComponentCodecQuant::LOSSLESS;
        let prog_quant = ComponentCodecQuant::LOSSLESS;

        let result = encode_first_pass(
            &mut coefficients,
            &mut output,
            &base_quant,
            &prog_quant,
            true, // reduce-extrapolate mode
        );

        assert!(result.is_ok(), "RLGR encode failed: {:?}", result.err());
        assert!(result.unwrap() > 0);
    }

    #[test]
    fn encode_upgrade_pass_empty_when_no_refinement() {
        let coefficients = [0i16; 4096];
        let mut sign = [SIGN_ZERO; 4096];

        // Same prog_quant for prev and curr -> num_bits = 0, no refinement
        let prog_quant = ComponentCodecQuant::LOSSLESS;

        let (srl_data, raw_data) = encode_upgrade_pass(&coefficients, &prog_quant, &prog_quant, &mut sign, false);

        assert!(srl_data.is_empty(), "no refinement bits, SRL should be empty");
        assert!(raw_data.is_empty(), "no refinement bits, raw should be empty");
    }

    /// Escale : passes successives (codeur et décodeur de la caisse) jusqu'à la pleine qualité :
    /// mêmes coefficients qu'une première passe en pleine qualité.
    #[test]
    fn upgrade_passes_converge_to_full_quality() {
        let base = ComponentCodecQuant { ll3: 6, hl3: 6, lh3: 6, hh3: 6, hl2: 6, lh2: 6, hh2: 6, hl1: 6, lh1: 6, hh1: 6 };
        let level = |ll3: u8, l3: u8, l2: u8, l1: u8| ComponentCodecQuant { ll3, hl3: l3, lh3: l3, hh3: l3, hl2: l2, lh2: l2, hh2: l2, hl1: l1, lh1: l1, hh1: l1 };
        let levels = [level(3, 4, 5, 6), level(1, 2, 3, 3), level(0, 1, 1, 2), ComponentCodecQuant::LOSSLESS];
        let spatial: [i16; 4096] = core::array::from_fn(|i| ((i * 37 % 251) as i16 - 125) * 16 + if (i % 64) % 7 == 1 { 1500 } else { -800 });
        let mut quantized = spatial;
        quantize_for_upgrade(&mut quantized, &base, true);

        let mut first = spatial;
        let mut data = vec![0u8; 16384];
        let n = encode_first_pass(&mut first, &mut data, &base, &levels[0], true).unwrap();
        let (mut coefficients, mut sign) = ([0i16; 4096], [0i8; 4096]);
        decode_first_pass(&data[..n], &base, &levels[0], true, &mut coefficients, &mut sign).unwrap();
        let mut enc_sign = sign;
        for w in levels.windows(2) {
            let (srl_data, raw_data) = encode_upgrade_pass(&quantized, &w[0], &w[1], &mut enc_sign, true);
            decode_upgrade_pass(&srl_data, &raw_data, &bit_positions(&base, &w[0]), &bit_positions(&base, &w[1]), true, &mut coefficients, &mut sign).unwrap();
            assert_eq!(sign, enc_sign);
        }

        let mut full = spatial;
        let n = encode_first_pass(&mut full, &mut data, &base, &ComponentCodecQuant::LOSSLESS, true).unwrap();
        let (mut want, mut want_sign) = ([0i16; 4096], [0i8; 4096]);
        decode_first_pass(&data[..n], &base, &ComponentCodecQuant::LOSSLESS, true, &mut want, &mut want_sign).unwrap();
        assert_eq!(coefficients, want);
    }
}
