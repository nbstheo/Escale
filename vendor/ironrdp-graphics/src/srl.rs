//! SRL (Simplified Run-Length) entropy codec for progressive upgrade passes.
//!
//! Used during progressive TILE_UPGRADE decoding where the tri-state sign
//! array (DAS) indicates zero-valued coefficients. SRL encodes/decodes
//! magnitudes for coefficients that were previously zero.
//!
//! The algorithm is similar to RLGR's zero-run mode with a simpler structure:
//! adaptive K parameter controlling zero-run lengths, followed by unary-coded
//! magnitudes with sign bits.

/// Escale : décodeur SRL à état, fidèle à FreeRDP (`progressive_rfx_srl_read`, MS-RDPEGFX
/// 3.2.8.1.x) : l'état (`kp` initialisé à 8, mode, zéros restants) est partagé par toutes les
/// bandes d'une composante, comme le flux de bits. L'ancienne version repartait de zéro à chaque
/// bande, démarrait avec `kp = 0`, lisait un bit de mode de trop après une suite de zéros et codait
/// la magnitude en quotient + reste : chaque passe d'amélioration était lue de travers.
pub struct SrlDecoder<'a> {
    reader: BitReader<'a>,
    kp: u32,
    nz: u32,
    /// Vrai : la valeur non nulle suit directement (codage unaire).
    unary: bool,
}

impl<'a> SrlDecoder<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            reader: BitReader::new(data),
            kp: 8,
            nz: 0,
            unary: false,
        }
    }

    /// Valeur suivante, sur `num_bits` bits de magnitude (≥ 1).
    pub fn read(&mut self, num_bits: u32) -> i16 {
        if self.nz > 0 {
            self.nz -= 1;
            return 0;
        }
        let k = self.kp / 8;
        if !self.unary {
            // codage des zéros
            if !self.reader.read_bit() {
                // '0' : une suite de 2^k zéros
                self.nz = 1 << k;
                self.kp = (self.kp + 4).min(80);
                self.nz -= 1;
                return 0;
            }
            // '1' : moins de 2^k zéros (k bits), puis une valeur non nulle
            self.unary = true;
            self.nz = self.reader.read_bits(k);
            if self.nz > 0 {
                self.nz -= 1;
                return 0;
            }
        }
        self.unary = false;
        let negative = self.reader.read_bit();
        self.kp = self.kp.saturating_sub(6);
        if num_bits <= 1 {
            return if negative { -1 } else { 1 };
        }
        let max = (1u32 << num_bits.min(16)) - 1;
        let mut mag = 1u32;
        while mag < max {
            if self.reader.read_bit() {
                break;
            }
            mag += 1;
        }
        let mag = i16::try_from(mag.min(0x7FFF)).unwrap_or(i16::MAX);
        if negative { -mag } else { mag }
    }

    /// Bits lus jusqu'ici.
    pub fn position(&self) -> usize {
        self.reader.byte_idx * 8 + usize::from(self.reader.bit_idx)
    }
}

/// Escale : codeur SRL symétrique de [`SrlDecoder`] (tests et encodeur progressif).
pub struct SrlEncoder {
    writer: BitWriter,
    kp: u32,
    zeros: u32,
}

impl Default for SrlEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl SrlEncoder {
    pub fn new() -> Self {
        Self {
            writer: BitWriter::new(),
            kp: 8,
            zeros: 0,
        }
    }

    /// Suites complètes de 2^k zéros.
    fn flush_runs(&mut self) {
        loop {
            let run = 1u32 << (self.kp / 8);
            if self.zeros < run {
                break;
            }
            self.writer.write_bit(false);
            self.zeros -= run;
            self.kp = (self.kp + 4).min(80);
        }
    }

    /// Ajoute une valeur ; sa magnitude est bornée à 2^`num_bits` - 1.
    pub fn push(&mut self, value: i16, num_bits: u32) {
        if value == 0 {
            self.zeros += 1;
            return;
        }
        self.flush_runs();
        let k = self.kp / 8;
        self.writer.write_bit(true);
        self.writer.write_bits(self.zeros, k);
        self.zeros = 0;
        self.writer.write_bit(value < 0);
        self.kp = self.kp.saturating_sub(6);
        if num_bits <= 1 {
            return;
        }
        let max = (1u32 << num_bits.min(16)) - 1;
        let mag = u32::from(value.unsigned_abs()).min(max);
        for _ in 1..mag {
            self.writer.write_bit(false);
        }
        if mag < max {
            self.writer.write_bit(true);
        }
    }

    pub fn finish(mut self) -> Vec<u8> {
        self.flush_runs();
        if self.zeros > 0 {
            // reste (< 2^k) : '1' + nombre de zéros ; la valeur qui suivrait n'est jamais lue
            let k = self.kp / 8;
            self.writer.write_bit(true);
            self.writer.write_bits(self.zeros, k);
        }
        self.writer.finish()
    }
}

/// Decode `num_values` SRL values of `num_bits` magnitude bits each (see [`SrlDecoder`]).
pub fn decode_srl(data: &[u8], num_values: usize, num_bits: u8) -> Vec<i16> {
    let mut decoder = SrlDecoder::new(data);
    (0..num_values).map(|_| decoder.read(u32::from(num_bits))).collect()
}

/// Encode values with `num_bits` magnitude bits each (see [`SrlEncoder`]).
pub fn encode_srl(values: &[i16], num_bits: u8) -> Vec<u8> {
    let mut encoder = SrlEncoder::new();
    for &v in values {
        encoder.push(v, u32::from(num_bits));
    }
    encoder.finish()
}

// ---------------------------------------------------------------------------
// Bit-level I/O helpers
// ---------------------------------------------------------------------------

struct BitReader<'a> {
    data: &'a [u8],
    byte_idx: usize,
    bit_idx: u8, // 0..7, MSB first
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            byte_idx: 0,
            bit_idx: 0,
        }
    }

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

    fn read_bits(&mut self, count: u32) -> u32 {
        let mut value = 0u32;
        for _ in 0..count {
            value = (value << 1) | u32::from(self.read_bit());
        }
        value
    }
}

struct BitWriter {
    bytes: Vec<u8>,
    current: u8,
    bit_count: u8, // bits written in current byte (0..7)
}

impl BitWriter {
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

    fn write_bits(&mut self, value: u32, count: u32) {
        for i in (0..count).rev() {
            self.write_bit((value >> i) & 1 != 0);
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.bit_count > 0 {
            // Pad remaining bits with zeros (MSB aligned)
            self.current <<= 8 - self.bit_count;
            self.bytes.push(self.current);
        }
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_empty() {
        let result = decode_srl(&[], 0, 1);
        assert!(result.is_empty());
    }

    #[test]
    fn decode_empty_data() {
        // With no data (empty slice), all positions default to zero
        let result = decode_srl(&[], 5, 1);
        assert_eq!(result, vec![0, 0, 0, 0, 0]);
    }

    #[test]
    fn encode_empty() {
        let encoded = encode_srl(&[], 1);
        assert!(encoded.is_empty());
    }

    #[test]
    fn encode_all_zeros() {
        let encoded = encode_srl(&[0, 0, 0], 1);
        // Round-trip: all zeros must survive
        let decoded = decode_srl(&encoded, 3, 1);
        assert_eq!(decoded, vec![0, 0, 0]);
    }

    #[test]
    fn round_trip_single_positive() {
        let original = vec![1];
        let encoded = encode_srl(&original, 1);
        let decoded = decode_srl(&encoded, 1, 1);
        assert_eq!(decoded, original);
    }

    #[test]
    fn round_trip_single_negative() {
        let original = vec![-1];
        let encoded = encode_srl(&original, 1);
        let decoded = decode_srl(&encoded, 1, 1);
        assert_eq!(decoded, original);
    }

    #[test]
    fn round_trip_mixed_zeros() {
        // Zeros at the start (where k=0) must survive the round-trip
        let original = vec![0, 0, 1, -1, 0, 3];
        let encoded = encode_srl(&original, 4);
        let decoded = decode_srl(&encoded, original.len(), 4);
        assert_eq!(decoded, original);
    }

    #[test]
    fn round_trip_nonzero_only() {
        let original = vec![1, -1, 2, -3, 1];
        let encoded = encode_srl(&original, 4);
        let decoded = decode_srl(&encoded, original.len(), 4);
        assert_eq!(decoded, original);
    }

    /// Vecteur construit à la main d'après `progressive_rfx_srl_read` (FreeRDP) : kp = 8 (k = 1) ;
    /// '0' -> 2 zéros (kp 12) ; '1' + '1' (k = 1) -> 1 zéro ; signe '0', kp 6 ; unaire '001' -> 3.
    #[test]
    fn decode_matches_freerdp_vector() {
        assert_eq!(decode_srl(&[0b0110_0010], 4, 3), vec![0, 0, 0, 3]);
        assert_eq!(encode_srl(&[0, 0, 0, 3], 3), vec![0b0110_0010]);
        // magnitude maximale (2^n - 1) : pas de bit de fin
        assert_eq!(decode_srl(&[0b1000_0000], 1, 2), vec![3]);
    }

    #[test]
    fn round_trip_long_runs() {
        let mut v = vec![0i16; 3000];
        for (i, x) in v.iter_mut().enumerate() {
            if i % 97 == 0 || i % 1000 == 999 {
                *x = if i % 2 == 0 { 5 } else { -7 };
            }
        }
        let encoded = encode_srl(&v, 3);
        assert_eq!(decode_srl(&encoded, v.len(), 3), v);
    }

    #[test]
    fn bit_reader_basic() {
        let data = [0b10110000];
        let mut reader = BitReader::new(&data);
        assert!(reader.read_bit()); // 1
        assert!(!reader.read_bit()); // 0
        assert!(reader.read_bit()); // 1
        assert!(reader.read_bit()); // 1
    }

    #[test]
    fn bit_writer_basic() {
        let mut writer = BitWriter::new();
        writer.write_bit(true);
        writer.write_bit(false);
        writer.write_bit(true);
        writer.write_bit(true);
        writer.write_bit(false);
        writer.write_bit(false);
        writer.write_bit(false);
        writer.write_bit(false);
        let result = writer.finish();
        assert_eq!(result, vec![0b10110000]);
    }

    #[test]
    fn bit_writer_multi_byte() {
        let mut writer = BitWriter::new();
        writer.write_bits(0xFF, 8);
        writer.write_bits(0x00, 8);
        let result = writer.finish();
        assert_eq!(result, vec![0xFF, 0x00]);
    }
}
