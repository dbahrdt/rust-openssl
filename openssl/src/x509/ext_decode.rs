use libc::{c_int, c_void};
use std::ptr;

use error::ErrorStack;
use foreign_types::{ForeignType, ForeignTypeRef};
use nid::Nid;
use stack::{Stack, StackRef};
use x509::{GeneralName, X509Extension, X509, X509Ref};

/// Parse X509 extensions from anything that contains a parsed form.
///
/// Methods returning a single extension instance return Ok(None) if the
/// extension doesn't exist, but Err(...) if parsing the extension failed.
///
/// The returned `bool` flag indicates whether the extension was flagged as
/// "critical".
pub trait X509ExtensionContainer: DecodeExtension {
    /// Returns the subject alternative name entries, if they exist.
    ///
    /// This corresponds to [`X509V3_get_d2i`] and friends called with `NID_subject_alt_name`.
    ///
    /// [`X509V3_get_d2i`]: https://www.openssl.org/docs/man1.1.0/crypto/X509V3_get_d2i.html
    fn subject_alt_names(&self) -> Result<Option<(Stack<GeneralName>, bool)>, ErrorStack> {
        unsafe {
            self.decode_extension_to::<Stack<GeneralName>>(Nid::SUBJECT_ALT_NAME, None)
        }
    }

    /// Returns the issuer alternative name entries, if they exist.
    ///
    /// This corresponds to [`X509V3_get_d2i`] and friends called with `NID_issuer_alt_name`.
    ///
    /// [`X509V3_get_d2i`]: https://www.openssl.org/docs/man1.1.0/crypto/X509V3_get_d2i.html
    fn issuer_alt_names(&self) -> Result<Option<(Stack<GeneralName>, bool)>, ErrorStack> {
        unsafe {
            self.decode_extension_to::<Stack<GeneralName>>(Nid::ISSUER_ALT_NAME, None)
        }
    }
}

impl<T: DecodeExtension> X509ExtensionContainer for T {}

/// Trait implemented by types which contain an X509 extension stack and have
/// direct accessor methods (see [`X509V3_get_d2i`]).
///
/// Types providing access to an extension stack might need to parse / create it
/// first; this step should be cached, and therefor no shortcut should be
/// provided here.
///
/// It should not be implemented for any type outside of this crate.
///
/// [`X509V3_get_d2i`]: https://www.openssl.org/docs/man1.1.0/crypto/X509V3_get_d2i.html
pub trait DecodeExtension {
    unsafe fn decode_extension_raw(&self, nid: c_int, crit: *mut c_int, idx: *mut c_int) -> *mut c_void;

    // use previous = Some(&mut -1) to find the first of multiple instances; None only finds single instances
    fn decode_extension(&self, nid: Nid, previous: Option<&mut c_int>) -> Result<Option<(*mut c_void, bool)>, ErrorStack> {
        let mut crit: c_int = -1;
        let result = unsafe {
            self.decode_extension_raw(nid.as_raw(), &mut crit, previous.map_or(ptr::null_mut(), |prev| prev as *mut _))
        };
        if result.is_null() {
            let err = ErrorStack::get();
            if err.errors().is_empty() {
                return Ok(None);
            } else {
                return Err(err);
            }
        }
        Ok(Some((result, crit == 1)))
    }

    unsafe fn decode_extension_to<T>(&self, nid: Nid, previous: Option<&mut c_int>) -> Result<Option<(T, bool)>, ErrorStack>
    where
        T: ForeignType,
    {
        Ok(self.decode_extension(nid, previous)?.map(|(ptr, crit)| {
            (T::from_ptr(ptr as *mut _), crit)
        }))
    }
}

impl DecodeExtension for Stack<X509Extension> {
    unsafe fn decode_extension_raw(&self, nid: c_int, crit: *mut c_int, idx: *mut c_int) -> *mut c_void {
        ffi::X509V3_get_d2i(self.as_ptr(), nid, crit, idx)
    }
}

impl DecodeExtension for StackRef<X509Extension> {
    unsafe fn decode_extension_raw(&self, nid: c_int, crit: *mut c_int, idx: *mut c_int) -> *mut c_void {
        ffi::X509V3_get_d2i(self.as_ptr(), nid, crit, idx)
    }
}

impl DecodeExtension for X509 {
    unsafe fn decode_extension_raw(&self, nid: c_int, crit: *mut c_int, idx: *mut c_int) -> *mut c_void {
        ffi::X509_get_ext_d2i(self.as_ptr(), nid, crit, idx)
    }
}

impl DecodeExtension for X509Ref {
    unsafe fn decode_extension_raw(&self, nid: c_int, crit: *mut c_int, idx: *mut c_int) -> *mut c_void {
        ffi::X509_get_ext_d2i(self.as_ptr(), nid, crit, idx)
    }
}

// missing: X509_CRL and X509_REVOKED
