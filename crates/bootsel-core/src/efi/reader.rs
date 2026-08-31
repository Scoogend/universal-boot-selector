//! Lecteur d'octets strictement borne.
//!
//! Toute lecture verifie ses bornes et renvoie une erreur typee. Il n'existe
//! aucun chemin de code capable de paniquer ou de lire hors du tampon : c'est
//! la garantie qui permet de parser sans risque des donnees firmware
//! potentiellement corrompues.

use super::EfiParseError;
use super::guid::Guid;

pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8], EfiParseError> {
        if self.remaining() < n {
            return Err(EfiParseError::UnexpectedEof {
                offset: self.pos,
                needed: n,
                available: self.remaining(),
            });
        }
        let slice = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    pub fn rest(&mut self) -> &'a [u8] {
        let slice = &self.buf[self.pos..];
        self.pos = self.buf.len();
        slice
    }

    pub fn u8(&mut self) -> Result<u8, EfiParseError> {
        Ok(self.take(1)?[0])
    }

    pub fn u16_le(&mut self) -> Result<u16, EfiParseError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn u32_le(&mut self) -> Result<u32, EfiParseError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u64_le(&mut self) -> Result<u64, EfiParseError> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    pub fn guid(&mut self) -> Result<Guid, EfiParseError> {
        let b = self.take(16)?;
        let mut raw = [0u8; 16];
        raw.copy_from_slice(b);
        Ok(Guid(raw))
    }

    /// Lit une chaine UCS-2 terminee par un caractere nul et consomme ce nul.
    ///
    /// Les unites de substitution invalides sont remplacees par U+FFFD plutot
    /// que de faire echouer le parsing : une description mal encodee ne doit
    /// pas rendre une entree de boot invisible.
    pub fn ucs2_nul_terminated(&mut self) -> Result<String, EfiParseError> {
        let start = self.pos;
        let mut units = Vec::new();
        loop {
            if self.remaining() < 2 {
                return Err(EfiParseError::UnterminatedString { offset: start });
            }
            let unit = self.u16_le()?;
            if unit == 0 {
                break;
            }
            units.push(unit);
        }
        Ok(char::decode_utf16(units)
            .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect())
    }

    /// Lit une chaine UCS-2 occupant exactement `bytes` octets, en s'arretant
    /// au premier nul rencontre (les octets restants sont du remplissage).
    pub fn ucs2_fixed(&mut self, bytes: usize) -> Result<String, EfiParseError> {
        let raw = self.take(bytes)?;
        let mut units = Vec::with_capacity(bytes / 2);
        for chunk in raw.chunks_exact(2) {
            let unit = u16::from_le_bytes([chunk[0], chunk[1]]);
            if unit == 0 {
                break;
            }
            units.push(unit);
        }
        Ok(char::decode_utf16(units)
            .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_integers_little_endian() {
        let data = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let mut r = Reader::new(&data);
        assert_eq!(r.u8().unwrap(), 0x01);
        assert_eq!(r.u16_le().unwrap(), 0x0302);
        assert_eq!(r.u32_le().unwrap(), 0x07060504);
        assert_eq!(r.remaining(), 1);
    }

    #[test]
    fn refuses_to_read_past_the_end() {
        let data = [0x01u8, 0x02];
        let mut r = Reader::new(&data);
        let err = r.u32_le().unwrap_err();
        assert!(matches!(
            err,
            EfiParseError::UnexpectedEof {
                needed: 4,
                available: 2,
                ..
            }
        ));
        // Le curseur n'a pas bouge : une lecture echouee ne consomme rien.
        assert_eq!(r.remaining(), 2);
    }

    #[test]
    fn empty_buffer_never_panics() {
        let mut r = Reader::new(&[]);
        assert!(r.u8().is_err());
        assert!(r.u16_le().is_err());
        assert!(r.guid().is_err());
        assert!(r.ucs2_nul_terminated().is_err());
        assert!(r.is_empty());
    }

    #[test]
    fn reads_nul_terminated_ucs2() {
        // "Debian\0"
        let mut data = Vec::new();
        for c in "Debian".encode_utf16() {
            data.extend_from_slice(&c.to_le_bytes());
        }
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&[0xAA, 0xBB]); // reliquat

        let mut r = Reader::new(&data);
        assert_eq!(r.ucs2_nul_terminated().unwrap(), "Debian");
        assert_eq!(r.remaining(), 2);
    }

    #[test]
    fn unterminated_ucs2_is_an_error_not_a_panic() {
        let mut data = Vec::new();
        for c in "Debian".encode_utf16() {
            data.extend_from_slice(&c.to_le_bytes());
        }
        let mut r = Reader::new(&data);
        assert!(matches!(
            r.ucs2_nul_terminated().unwrap_err(),
            EfiParseError::UnterminatedString { .. }
        ));
    }

    #[test]
    fn fixed_ucs2_stops_at_first_nul() {
        let mut data = Vec::new();
        for c in "grub".encode_utf16() {
            data.extend_from_slice(&c.to_le_bytes());
        }
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&[0xFF, 0xFF]); // remplissage apres le nul

        let mut r = Reader::new(&data);
        assert_eq!(r.ucs2_fixed(12).unwrap(), "grub");
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn invalid_utf16_becomes_replacement_char_not_an_error() {
        // Surrogate haut isole : encodage invalide, mais ne doit pas echouer.
        let data = [0x00, 0xD8, 0x00, 0x00];
        let mut r = Reader::new(&data);
        assert_eq!(r.ucs2_nul_terminated().unwrap(), "\u{FFFD}");
    }
}
