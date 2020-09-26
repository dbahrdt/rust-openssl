use nid::Nid;
use stack::Stack;
use x509::GeneralName;

use super::ExtensionMark;

/// Marker type to decode `SubjectAltName`
pub struct ExtSubjectAltName;
unsafe impl ExtensionMark for ExtSubjectAltName {
    type Data = Stack<GeneralName>;
    const NID: Nid = Nid::SUBJECT_ALT_NAME;
}

/// Marker type to decode `IssuerAltName`
pub struct ExtIssuerAltName;
unsafe impl ExtensionMark for ExtIssuerAltName {
    type Data = Stack<GeneralName>;
    const NID: Nid = Nid::ISSUER_ALT_NAME;
}
