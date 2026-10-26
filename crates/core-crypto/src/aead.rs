#[cfg(feature = "tls12")]
use aead::Buffer;
#[cfg(feature = "tls12")]
use rustls::crypto::cipher::{BorrowedPayload, PrefixedPayload};

pub mod chacha20;
pub mod gcm;

#[cfg(feature = "tls12")]
pub(crate) struct EncryptBufferAdapter<'a>(&'a mut PrefixedPayload);

#[cfg(feature = "tls12")]
impl AsRef<[u8]> for EncryptBufferAdapter<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[cfg(feature = "tls12")]
impl AsMut<[u8]> for EncryptBufferAdapter<'_> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

#[cfg(feature = "tls12")]
impl Buffer for EncryptBufferAdapter<'_> {
    fn extend_from_slice(&mut self, other: &[u8]) -> aead::Result<()> {
        self.0.extend_from_slice(other);
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        self.0.truncate(len)
    }
}

#[cfg(feature = "tls12")]
pub(crate) struct DecryptBufferAdapter<'a, 'p>(&'a mut BorrowedPayload<'p>);

#[cfg(feature = "tls12")]
impl AsRef<[u8]> for DecryptBufferAdapter<'_, '_> {
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}

#[cfg(feature = "tls12")]
impl AsMut<[u8]> for DecryptBufferAdapter<'_, '_> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0
    }
}

#[cfg(feature = "tls12")]
impl Buffer for DecryptBufferAdapter<'_, '_> {
    fn extend_from_slice(&mut self, _: &[u8]) -> aead::Result<()> {
        unreachable!("not used by `AeadInPlace::decrypt_in_place`")
    }

    fn truncate(&mut self, len: usize) {
        self.0.truncate(len)
    }
}
