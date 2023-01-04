//! ContentInfo types
use core::cmp::Ordering;

use const_oid::ObjectIdentifier;

use der::{AnyRef, Enumerated, Sequence, ValueOrd};

/// The `OtherCertificateFormat` type is defined in [RFC 5652 Section 10.2.5].
///
/// ```text
///  CMSVersion ::= INTEGER  { v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }
/// ```
///
/// [RFC 5652 Section 10.2.5]: https://www.rfc-editor.org/rfc/rfc5652#section-10.2.5
#[derive(Clone, Debug, Copy, PartialEq, Eq, PartialOrd, Ord, Enumerated)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
#[allow(missing_docs)]
pub enum CmsVersion {
    V0 = 0,
    V1 = 1,
    V2 = 2,
    V3 = 3,
    V4 = 4,
    V5 = 5,
}

// TODO DEFER ValueOrd procedural macro appears not to work for enums
impl ValueOrd for CmsVersion {
    fn value_cmp(&self, other: &Self) -> der::Result<Ordering> {
        #[allow(unused_imports)]
        use ::der::DerOrd;
        if self == other {
            Ok(::core::cmp::Ordering::Equal)
        } else if self < other {
            Ok(::core::cmp::Ordering::Less)
        } else {
            Ok(::core::cmp::Ordering::Greater)
        }
    }
}

/// The `ContentInfo` type is defined in [RFC 5652 Section 3].
///
/// ```text
///   ContentInfo ::= SEQUENCE {
///       contentType        CONTENT-TYPE.
///                       &id({ContentSet}),
///       content            [0] EXPLICIT CONTENT-TYPE.
///                       &Type({ContentSet}{@contentType})}
/// ```
///
/// [RFC 5652 Section 3]: https://www.rfc-editor.org/rfc/rfc5652#section-3
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct ContentInfo<'a> {
    pub content_type: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    pub content: AnyRef<'a>,
}
