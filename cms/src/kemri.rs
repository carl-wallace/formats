//! KEM-related types from draft-ietf-lamps-cms-kemri-06

use der::asn1::OctetString;
use der::Sequence;
use spki::AlgorithmIdentifierOwned;
use crate::content_info::CmsVersion;
use crate::enveloped_data::{EncryptedKey, RecipientIdentifier, UserKeyingMaterial};

/// The `KEMRecipientInfo` type is defined in [draft-ietf-lamps-cms-kemri Section 3].
///
/// ```text
/// KEMRecipientInfo ::= SEQUENCE {
///     version CMSVersion,  -- always set to 0
///     rid RecipientIdentifier,
///     kem KEMAlgorithmIdentifier,
///     kemct OCTET STRING,
///     kdf KeyDerivationAlgorithmIdentifier,
///     kekLength INTEGER (1..65535),
///     ukm [0] EXPLICIT UserKeyingMaterial OPTIONAL,
///     wrap KeyEncryptionAlgorithmIdentifier,
///     encryptedKey EncryptedKey 
/// }
/// ```
/// [draft-ietf-lamps-cms-kemri Section 3]: https://datatracker.ietf.org/doc/html/draft-ietf-lamps-cms-kemri-06#section-3
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct KemRecipientInfo {
    pub version: CmsVersion,
    pub rid: RecipientIdentifier,
    pub kem: AlgorithmIdentifierOwned,
    pub kem_ct: OctetString,
    pub kdf: AlgorithmIdentifierOwned,
    pub kek_length: u16,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub ukm: Option<UserKeyingMaterial>,
    pub wrap: AlgorithmIdentifierOwned,
    pub encrypted_key: EncryptedKey
}
