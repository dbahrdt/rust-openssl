use foreign_types::{ForeignType, ForeignTypeRef};
use libc::{c_int, c_void};
use x509::{X509Crl, X509CrlRef};

use super::{sealed, RawExtensionAccess};

impl sealed::ExtensionAccess for X509Crl {}
impl RawExtensionAccess for X509Crl {
    fn raw_get_ext_count(&self) -> c_int {
        unsafe { ffi::X509_CRL_get_ext_count(self.as_ptr()) }
    }
    fn raw_get_ext_by_nid(&self, nid: c_int, lastpos: c_int) -> c_int {
        unsafe { ffi::X509_CRL_get_ext_by_NID(self.as_ptr(), nid, lastpos) }
    }
    unsafe fn raw_get_ext_by_obj(&self, obj: *const ffi::ASN1_OBJECT, lastpos: c_int) -> c_int {
        ffi::X509_CRL_get_ext_by_OBJ(self.as_ptr(), obj, lastpos)
    }
    fn raw_get_ext_by_critical(&self, crit: c_int, lastpos: c_int) -> c_int {
        unsafe { ffi::X509_CRL_get_ext_by_critical(self.as_ptr(), crit, lastpos) }
    }
    fn raw_get_ext(&self, loc: c_int) -> *mut ffi::X509_EXTENSION {
        unsafe { ffi::X509_CRL_get_ext(self.as_ptr(), loc) }
    }
    unsafe fn raw_get_ext_d2i(&self, nid: c_int, crit: *mut c_int, idx: *mut c_int) -> *mut c_void {
        ffi::X509_CRL_get_ext_d2i(self.as_ptr(), nid, crit, idx)
    }
}
// X509Crl immutable; no builder yet
// impl RawExtensionModify for X509Crl { }

impl sealed::ExtensionAccess for X509CrlRef {}
impl RawExtensionAccess for X509CrlRef {
    fn raw_get_ext_count(&self) -> c_int {
        unsafe { ffi::X509_CRL_get_ext_count(self.as_ptr()) }
    }
    fn raw_get_ext_by_nid(&self, nid: c_int, lastpos: c_int) -> c_int {
        unsafe { ffi::X509_CRL_get_ext_by_NID(self.as_ptr(), nid, lastpos) }
    }
    unsafe fn raw_get_ext_by_obj(&self, obj: *const ffi::ASN1_OBJECT, lastpos: c_int) -> c_int {
        ffi::X509_CRL_get_ext_by_OBJ(self.as_ptr(), obj, lastpos)
    }
    fn raw_get_ext_by_critical(&self, crit: c_int, lastpos: c_int) -> c_int {
        unsafe { ffi::X509_CRL_get_ext_by_critical(self.as_ptr(), crit, lastpos) }
    }
    fn raw_get_ext(&self, loc: c_int) -> *mut ffi::X509_EXTENSION {
        unsafe { ffi::X509_CRL_get_ext(self.as_ptr(), loc) }
    }
    unsafe fn raw_get_ext_d2i(&self, nid: c_int, crit: *mut c_int, idx: *mut c_int) -> *mut c_void {
        ffi::X509_CRL_get_ext_d2i(self.as_ptr(), nid, crit, idx)
    }
}
// X509Crl immutable; no builder yet
// impl RawExtensionModify for X509CrlRef { }
