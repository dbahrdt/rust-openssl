use foreign_types::{ForeignType, ForeignTypeRef};
use libc::{c_int, c_ulong, c_void};
use x509::{X509Builder, X509Ref, X509};

use super::{sealed, RawExtensionAccess, RawExtensionModify};

impl sealed::ExtensionAccess for X509Builder {}
impl RawExtensionAccess for X509Builder {
    fn raw_get_ext_count(&self) -> c_int {
        unsafe { ffi::X509_get_ext_count(self.0.as_ptr()) }
    }
    fn raw_get_ext_by_nid(&self, nid: c_int, lastpos: c_int) -> c_int {
        unsafe { ffi::X509_get_ext_by_NID(self.0.as_ptr(), nid, lastpos) }
    }
    unsafe fn raw_get_ext_by_obj(&self, obj: *const ffi::ASN1_OBJECT, lastpos: c_int) -> c_int {
        ffi::X509_get_ext_by_OBJ(self.0.as_ptr(), obj, lastpos)
    }
    fn raw_get_ext_by_critical(&self, crit: c_int, lastpos: c_int) -> c_int {
        unsafe { ffi::X509_get_ext_by_critical(self.0.as_ptr(), crit, lastpos) }
    }
    fn raw_get_ext(&self, loc: c_int) -> *mut ffi::X509_EXTENSION {
        unsafe { ffi::X509_get_ext(self.0.as_ptr(), loc) }
    }
    unsafe fn raw_get_ext_d2i(&self, nid: c_int, crit: *mut c_int, idx: *mut c_int) -> *mut c_void {
        ffi::X509_get_ext_d2i(self.0.as_ptr(), nid, crit, idx)
    }
}
impl RawExtensionModify for X509Builder {
    fn raw_delete_ext(&mut self, loc: c_int) -> *mut ffi::X509_EXTENSION {
        unsafe { ffi::X509_delete_ext(self.0.as_ptr(), loc) }
    }
    unsafe fn raw_add_ext(&mut self, ex: *mut ffi::X509_EXTENSION, loc: c_int) -> bool {
        let result = ffi::X509_add_ext(self.0.as_ptr(), ex, loc);
        result != 0
    }
    unsafe fn raw_add1_i2d(
        &mut self,
        nid: c_int,
        value: *mut c_void,
        crit: c_int,
        flags: c_ulong,
    ) -> c_int {
        ffi::X509_add1_ext_i2d(self.0.as_ptr(), nid, value, crit, flags)
    }
}

impl sealed::ExtensionAccess for X509 {}
impl RawExtensionAccess for X509 {
    fn raw_get_ext_count(&self) -> c_int {
        unsafe { ffi::X509_get_ext_count(self.as_ptr()) }
    }
    fn raw_get_ext_by_nid(&self, nid: c_int, lastpos: c_int) -> c_int {
        unsafe { ffi::X509_get_ext_by_NID(self.as_ptr(), nid, lastpos) }
    }
    unsafe fn raw_get_ext_by_obj(&self, obj: *const ffi::ASN1_OBJECT, lastpos: c_int) -> c_int {
        ffi::X509_get_ext_by_OBJ(self.as_ptr(), obj, lastpos)
    }
    fn raw_get_ext_by_critical(&self, crit: c_int, lastpos: c_int) -> c_int {
        unsafe { ffi::X509_get_ext_by_critical(self.as_ptr(), crit, lastpos) }
    }
    fn raw_get_ext(&self, loc: c_int) -> *mut ffi::X509_EXTENSION {
        unsafe { ffi::X509_get_ext(self.as_ptr(), loc) }
    }
    unsafe fn raw_get_ext_d2i(&self, nid: c_int, crit: *mut c_int, idx: *mut c_int) -> *mut c_void {
        ffi::X509_get_ext_d2i(self.as_ptr(), nid, crit, idx)
    }
}
// X509 is immutable; use X509Builder for modifications
// impl RawExtensionModify for X509 { }

impl sealed::ExtensionAccess for X509Ref {}
impl RawExtensionAccess for X509Ref {
    fn raw_get_ext_count(&self) -> c_int {
        unsafe { ffi::X509_get_ext_count(self.as_ptr()) }
    }
    fn raw_get_ext_by_nid(&self, nid: c_int, lastpos: c_int) -> c_int {
        unsafe { ffi::X509_get_ext_by_NID(self.as_ptr(), nid, lastpos) }
    }
    unsafe fn raw_get_ext_by_obj(&self, obj: *const ffi::ASN1_OBJECT, lastpos: c_int) -> c_int {
        ffi::X509_get_ext_by_OBJ(self.as_ptr(), obj, lastpos)
    }
    fn raw_get_ext_by_critical(&self, crit: c_int, lastpos: c_int) -> c_int {
        unsafe { ffi::X509_get_ext_by_critical(self.as_ptr(), crit, lastpos) }
    }
    fn raw_get_ext(&self, loc: c_int) -> *mut ffi::X509_EXTENSION {
        unsafe { ffi::X509_get_ext(self.as_ptr(), loc) }
    }
    unsafe fn raw_get_ext_d2i(&self, nid: c_int, crit: *mut c_int, idx: *mut c_int) -> *mut c_void {
        ffi::X509_get_ext_d2i(self.as_ptr(), nid, crit, idx)
    }
}
// X509 is immutable; use X509Builder for modifications
// impl RawExtensionModify for X509Ref { }
