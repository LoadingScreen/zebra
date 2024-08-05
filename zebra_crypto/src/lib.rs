mod ristretto;

use ristretto::{RistrettoPoint, Scalar};

use std::str::FromStr;

use boringascii::BoringAscii;
use borsh::{BorshDeserialize, BorshSerialize};
use sha3::{Digest, Sha3_256, Sha3_512};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Make a ring of public keys. First, we add the public key corresponding to the given private key
/// to the list of possible signers. Then we sort the ring by the members' compressed
/// RistrettoPoints. That way, all properties of the ring are determined entirely by the choice of
/// keys, and not at all by randomness (or, worse, any difference between the private and public
/// keys).
fn make_ring<T: Clone, F: Fn(T) -> RistrettoPoint>(
    my_key: T,
    other_keys: &[T],
    key_extractor: F,
) -> Vec<T> {
    let ring_size = other_keys.len() + 1;
    let mut ring = Vec::with_capacity(ring_size);
    ring.extend_from_slice(other_keys);
    ring.push(my_key.clone());
    ring.sort_by_key(|k| key_extractor(k.clone()).compress());
    ring
}

/// Generate the hash of the message and public keys in the ring. This serves as the mathematical
/// object that is actually "signed" in the ring signature scheme.
fn hash_message_and_ring<'a>(
    message: &[u8],
    keys: impl Iterator<Item = &'a RistrettoPoint>,
) -> Sha3_512 {
    let mut message_and_ring_hash = Sha3_512::new_with_prefix(message);
    for keypoint in keys {
        message_and_ring_hash.update(keypoint.compress())
    }
    message_and_ring_hash
}

#[derive(
    Clone, PartialEq, Eq, PartialOrd, Ord, Zeroize, ZeroizeOnDrop, BorshSerialize, BorshDeserialize,
)]
pub struct Signature {
    challenge: Scalar,
    ring_responses: Vec<(RistrettoPoint, Scalar)>,
}

impl Signature {
    /// Compute a ring signature of the given message, using the given private key, such that the
    /// signature could have been produced by any of the holders of the given public keys (those
    /// passed in directly, or the one that can be generated from the given private key).
    ///
    /// Sources:
    /// https://web.archive.org/web/20230526135545/https://www.getmonero.org/library/Zero-to-Monero-2-0-0.pdf
    /// (https://www.getmonero.org/library/Zero-to-Monero-2-0-0.pdf; public domain) (page 27-29)
    /// https://archive.ph/rtOuB (https://github.com/edwinhere/nazgul/blob/master/src/sag.rs;
    /// MIT-licensed)
    /// https://archive.ph/EsIX0 (https://github.com/zudo/ring-signature/blob/main/src/sag.rs;
    /// unlicensed as far as I can tell)
    ///
    /// In writing this code, I primarily relied on Zero to Monero: Second Edition, with moderate
    /// double-checking against the first file linked above (edwinhere's SAG implementation). I
    /// glanced at the third resource linked above (zudo's impelementation) once or twice; it seems
    /// to have been written 3 months ago (as of September 2023), whereas edwinhere's version was
    /// written 3 years ago. Based on the strong similarity between the two implementations, I'd
    /// have to guess that zudo's implementation was at least inspired by edwinhere's. IMO this
    /// version is cleaner and easier-to-audit than either of theirs, due to carefully simplifying
    /// the iteration over the ring members.
    ///
    /// Copyright-wise, I'm confident that this implementation is *not* a derivative work of zudo's
    /// implementation, as I barely glanced at it to double-check my understanding of edwinhere's
    /// implementation. It's possible that this *could* be a derivative of edwinhere's
    /// implementation, though I did mainly write it from scratch. However, this may constrain me
    /// to publish this section of code under an MIT license
    fn sign(
        message: &[u8],                            // m
        my_private_value: Scalar,                  // k_pi
        other_public_keypoints: &[RistrettoPoint], // K_i
    ) -> Self {
        // K_pi
        let my_public_keypoint = RistrettoPoint::mul_base(&my_private_value);

        // n
        let ring_size = other_public_keypoints.len() + 1;

        // R
        let ring = make_ring(my_public_keypoint.clone(), other_public_keypoints, |k| k);

        // pi
        let my_key_index = ring
            .binary_search_by_key(&my_public_keypoint.compress(), |k| k.compress())
            .expect("Key just inserted into vec, but missing after sorting.");

        // initialized to be fake responses r_i
        let mut responses: Vec<Scalar> = (0..ring_size).map(|_| Scalar::random()).collect();

        let mut cs: Vec<Scalar> = vec![Scalar::ZERO; ring_size];

        let a = Scalar::random();
        // c_{pi + 1} = H_n(R, m, [aG])
        let initial_hash = hash_message_and_ring(message, ring.iter());
        let mut next_hash_update = RistrettoPoint::mul_base(&a);

        for offset_from_my_key in 1..ring_size + 1 {
            let index = (my_key_index + offset_from_my_key) % ring_size;

            // C_{i + 1} = H_n(R, M, [r_i G + c_i K_i])
            let mut hash = initial_hash.clone();
            hash.update(next_hash_update.compress());
            cs[index] = Scalar::from_hash(hash);
            next_hash_update =
                RistrettoPoint::mul_base(&responses[index]) + cs[index].clone() * &ring[index];
        }

        // "Define the real response r_pi such that a = r_pi + c_pi k_pi (mod l)", i.e. r_pi = a -
        // c_pi k_pi (mod l)
        // this is the "key" step: If we didn't know one of the private keys, we couldn't compute
        // the ring signature. Without the private key corresponding to K_pi, this equation would
        // be unsolvable.
        responses[my_key_index] = a - (cs[my_key_index].clone() * my_private_value);

        Self {
            challenge: cs[0].clone(),
            ring_responses: ring.into_iter().zip(responses).collect(),
        }
    }

    /// Verify that this is a valid signature of the given message. That is, one of the holders of
    /// the private keys corresponding to the public keys in the ring, must have produced this
    /// signature.
    fn verify(&self, message: &[u8]) -> bool {
        // c_{i + 1}' = H_n(R, m, [r_i G + c_i K_i])
        let initial_hash =
            hash_message_and_ring(message, self.ring_responses.iter().map(|(k, _)| k));

        let mut reconstructed_challenge = self.challenge.clone();

        for (keypoint, response) in &self.ring_responses {
            let mut h = initial_hash.clone();
            let hash_update =
                RistrettoPoint::mul_base(response) + reconstructed_challenge * keypoint;
            h.update(hash_update.compress());
            reconstructed_challenge = Scalar::from_hash(h);
        }

        // c_1 == c_1'
        self.challenge == reconstructed_challenge
    }
}

/// An identity used for creating a ring signature.
///
/// An identity always contains a name and an email address. The name can be almost any utf-8
/// string: The only exception is that it cannot contain control codes (including e.g. newlines).
/// This ensures that we can cleanly serialize and deserialize it from a single line. The email
/// address can be only ASCII strings that are both printable and not whitespace. This is a brute-force
/// method for preventing homoglyph attacks: In the future, we may add functionality for
/// semi-automatically (weakly) verifying public keys over email. In that case, it's important that
/// any email address that looks like a familiar one actually *is* that address and not a different
/// one. Fortunately, even email addresses in regions that primarily use alternative character sets
/// very rarely use non-ASCII characters.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Zeroize, ZeroizeOnDrop, BorshSerialize)]
pub struct Identity {
    name: String,
    email: BoringAscii,
}

impl Identity {
    pub fn new(name: &str, email: &str) -> Option<Self> {
        if name.contains(char::is_control) {
            return None;
        }
        Some(Self {
            name: name.to_string(),
            email: BoringAscii::from_str(email).ok()?,
        })
    }

    pub fn name(&self) -> String {
        self.name.clone()
    }

    pub fn email(&self) -> String {
        self.email.to_string()
    }

    /// The information that, when signed and verified, suffices to prove that the given public
    /// keypoint belongs to someone who claims this identity.
    fn bytes_for_attestation(&self, keypoint: &RistrettoPoint) -> Vec<u8> {
        let mut result = vec![];
        // This text could be anything or nothing in principle, but it's good to make it obvious
        // when a malicious source might be leading a user to make a bogus attestation.
        result.extend_from_slice(
            "!!!DO NOT SIGN THE FOLLOWING MESSAGE. DOING SO IS A SECURITY RISK. SOMEONE IS PROBABLY TRYING TO TRICK YOU!!!".as_bytes(),
        );
        result.extend_from_slice(self.name.as_bytes());
        result.extend_from_slice(&[0xff]); // sentinel separating holder's name and email. Not a
                                           // valid UTF-8 or ASCII byte.
        result.extend_from_slice(self.email.as_bytes());
        result.extend_from_slice(&keypoint.compress());
        result
    }
}

// We implement deserialize explicitly because the derived impl would not check our invariants (no
// control characters in the identity, and no non-printable or whitespace characters in the email
// address)
impl BorshDeserialize for Identity {
    fn deserialize_reader<R: std::io::Read>(r: &mut R) -> std::io::Result<Identity> {
        let name = String::deserialize_reader(r)?;
        let email = BoringAscii::deserialize_reader(r)?;
        Identity::new(&name, email.as_str()).ok_or(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Error constructing Identity",
        ))
    }
}

/// To allow forward compatibility, we excplicitly include a version string in both keys and
/// messages. Each element of this enum corresponds to an ASCII string via the listed constants,
/// and cannot contain angle bracket characters for the public key format to be parsable. Newlines
/// and other whitespace or control characters are also not allowed, while spaces are ok.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Zeroize, ZeroizeOnDrop, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
enum ZebraVersion {
    ZebraOneBeta = 0,
}

const ZEBRA_ONE_BETA: &str = "ZebraSign 1.0 Beta";

impl From<&ZebraVersion> for String {
    fn from(value: &ZebraVersion) -> Self {
        match value {
            ZebraVersion::ZebraOneBeta => String::from(ZEBRA_ONE_BETA),
        }
    }
}

impl ToString for ZebraVersion {
    fn to_string(&self) -> String {
        From::from(self)
    }
}

impl std::str::FromStr for ZebraVersion {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            ZEBRA_ONE_BETA => Ok(ZebraVersion::ZebraOneBeta),
            _ => Err(()),
        }
    }
}

/// A complete public key, containing all the information required to share the key with others, to
/// store it to disk, or to take part in a ring signature or verification. The attestation of a
/// constructed PublicKey object *may not be valid*. This must be checked before relying on the
/// key's validity.
#[derive(
    Clone, PartialEq, Eq, PartialOrd, Ord, Zeroize, ZeroizeOnDrop, BorshSerialize, BorshDeserialize,
)]
pub struct PublicKey {
    holder: Identity,
    version: ZebraVersion,
    keypoint: RistrettoPoint,

    // We want a public key to be a simple package that can be imported into an app without
    // additional user input (e.g. associating the key with an identity). Thus the public key
    // structure should include the identity as well as the key material. But in that case, we want
    // to make it difficult for a mistaken or malicious party to cause a user to import key
    // material with the wrong identity associated.

    // This is a single-entry ring signature of the identity and the public keypoint, made by the
    // corresponding secret key. This ensures that the person with this keypair (at least) claims
    // to have the given identity. Thus a client app can refuse to import a pair that mismatches
    // the identity to the key material. And because a message signature only ensures the integrity
    // of the ring keypoints and not the associated identities, this attestation also enables
    // enforcing that the identities associated with a signed message haven't been tampered with,
    // e.g. by an intermediary. In some sense it would be simpler to use a DSA signature instead
    // of a ring signature, but in practice that would be unnecessary extra code or an extra
    // dependency.
    holder_attestation: Signature,
}

impl PublicKey {
    pub fn holder(&self) -> Identity {
        self.holder.clone()
    }

    pub fn keypoint(&self) -> RistrettoPoint {
        self.keypoint.clone()
    }

    pub fn holder_attestation(&self) -> Signature {
        self.holder_attestation.clone()
    }

    /// Verify that the holder of this public key's corresponding private key has claimed that the
    /// key belongs to the indicated identity.
    fn validate_attestation(&self) -> bool {
        if self.holder_attestation.ring_responses.len() != 1 {
            return false;
        }
        if self.holder_attestation.ring_responses[0].0 != self.keypoint {
            return false;
        }
        self.holder_attestation
            .verify(&self.holder.bytes_for_attestation(&self.keypoint))
    }

    /// The z85-encoded fingerprint. This fingerprint has spaces inserted after every 8-byte
    /// (10-character) chunk of the key. This ensures a simple, more-readable, and consistent view
    /// of the fingerprint data.
    pub fn fingerprint(&self) -> String {
        let mut buffer = vec![];
        let _ = self.serialize(&mut buffer);
        let mut res = z85::encode(Sha3_256::digest(buffer))
            .chars()
            .collect::<Vec<_>>();
        res.insert(30, ' ');
        res.insert(20, ' ');
        res.insert(10, ' ');
        res.into_iter().collect()
    }
}

// The ASCII format for a public key looks like:
// [Ben Weinstein-Raun <b@w-r.me> <Zebra 1.0 Beta> AC9AD3F7086D6B34F91AD868D332A34CCB75E2CFD6CCDB99596DA0534CF8C23B 6F2CFB8088A7D3FCF20E0E801BAF0599649D2366D90AC28214EEAC4F23DD8B0801000000AC9AD3F7086D6B34F91AD868D332A34CCB75E2CFD6CCDB99596DA0534CF8C23B82E6357B982AD71F5E8E34FC83F56218225C88A1E2582C4EEC2D7A2A505DFC08]
// The parts here are:
// - open square bracket ("[")
// - the name (which can contain any non-control utf-8 characters)
// - space and open angle bracket (" <")
// - the email (which can contain only non-whitespace non-control ascii characters)
// - close angle bracket and space ("> ")
// - space and open angle bracket (" <")
// - the version string (which must match one of the version strings listed above exactly)
// - close angle bracket and space ("> ")
// - the hex-encoded compressed ristretto point (64 uppercase hex digits)
// - space (" ")
// - the hex-encoded holder attestation (200 uppercase hex digits)
// - close square bracket ("]")
//
// Since the name can contain nearly-arbitrary characters, the key must be parsed from the back as
// well as the front: The first character must be an open angle bracket, but reading in that
// direction, it's never clear when the name ends. The string must *end* with the fixed-sized hex
// ascii attestation and public key, just before that is a version string enclosed by angle brackts,
// and just before that is an email address that cannot contain spaces, in turn preceded by a space
// character. Thus, this encoding is bijective and unambiguous in both directions. Also, because the 
// name, email address and version string cannot contain newlines, we can encode lists of public keys 
// as newline-separated strings.
impl From<PublicKey> for String {
    fn from(k: PublicKey) -> String {
        let mut buffer = vec![];
        k.holder_attestation
            .serialize(&mut buffer)
            .expect("Serialization into unbounded vec failed");
        format!(
            "[{} <{}> <{}> {} {}]",
            k.holder.name,
            k.holder.email,
            k.version.to_string(),
            hex::encode_upper(k.keypoint.compress()),
            hex::encode_upper(buffer)
        )
    }
}

impl FromStr for PublicKey {
    type Err = ();
    fn from_str(s: &str) -> Result<PublicKey, ()> {
        use regex::Regex;
        // This regex should exactly match the description above, and not allow any matches that
        // don't fit the pattern described. Fortunately it's pretty simple.
        let re = match Regex::new(&format!(r"^\[([^\n]*) <([!-~]*)> <{}> ([0-9A-F]{{64}}) ([0-9A-F]{{200}})\]$", ZEBRA_ONE_BETA)) {
            Ok(re) => re,
            Err(_) => return Err(()),
        };

        let mut caps = re.captures_iter(s).map(|c| c.extract());
        let (name, email, keypoint, attestation) = match caps.next() {
            Some((overall, [name, email, keypoint, attestation])) => {
                if overall.len() != s.len() {
                    return Err(());
                }
                (name, email, keypoint, attestation)
            }
            _ => return Err(()),
        };

        let id = Identity::new(name, email).ok_or(())?;

        let keypoint = hex::decode(keypoint).map_err(|_| ())?;
        let attestation = hex::decode(attestation).map_err(|_| ())?;

        let keypoint = curve25519_dalek::ristretto::CompressedRistretto::from_slice(&keypoint)
            .map_err(|_| ())?
            .decompress()
            .ok_or(())?;
        let attestation = Signature::deserialize(&mut attestation.as_ref()).map_err(|_| ())?;

        let res = PublicKey {
            holder: id,
            version: ZebraVersion::ZebraOneBeta,
            keypoint: RistrettoPoint(keypoint),
            holder_attestation: attestation,
        };

        if !res.validate_attestation() {
            return Err(());
        }

        Ok(res)
    }
}

/// A complete private key, containing all the information required to store it to disk, or to
/// produce new ring signatures.
#[derive(
    Clone, PartialEq, Eq, Ord, PartialOrd, Zeroize, ZeroizeOnDrop, BorshSerialize, BorshDeserialize,
)]
pub struct PrivateKey {
    pub holder: Identity,
    key: Scalar,
    // We store the holder attestation in the private key as well as the public key, because we
    // don't want to generate distinct attestations for the same keypair: Because each attestation
    // includes a randomly-generated challenge, each independently-generated attestation will be
    // different. Cryptographically this shouldn't matter, but it's nice to have only one canonical
    // public key rather than an endless stream of them.
    holder_attestation: Signature,
}

impl PrivateKey {
    pub fn new(holder: Identity) -> Self {
        let key = Scalar::random();
        PrivateKey {
            holder_attestation: Signature::sign(
                &holder.bytes_for_attestation(&RistrettoPoint::mul_base(&key)),
                key.clone(),
                &[],
            ),
            holder,
            key: key.clone(),
        }
    }

    pub fn public(&self) -> PublicKey {
        PublicKey {
            holder: self.holder.clone(),
            version: ZebraVersion::ZebraOneBeta,
            keypoint: RistrettoPoint::mul_base(&self.key),
            holder_attestation: self.holder_attestation.clone(),
        }
    }
}

/// A signed message. Contains enough information to verify that one of the given set of public keys
/// signed the included message (and that those keys claim to correspond to the given identities).
#[derive(Clone, PartialEq, Zeroize, ZeroizeOnDrop, BorshSerialize, BorshDeserialize)]
pub struct SignedMessage {
    pub message: String,
    challenge: Scalar,
    ring: Vec<(PublicKey, Scalar)>,
}

impl SignedMessage {
    pub fn sign(message: &str, my_key: &PrivateKey, other_keys: &[PublicKey]) -> Self {
        let my_public_key = my_key.public();
        // If someone selected both their public and private key, we don't want to give them away
        // by including both in the ring.
        let other_keys = other_keys
            .iter()
            .cloned()
            .filter(|k| k != &my_public_key)
            .collect::<Vec<_>>();

        let sig = Signature::sign(
            message.as_bytes(),
            my_key.key.clone(),
            &other_keys
                .iter()
                .map(|k| k.keypoint.clone())
                .collect::<Vec<_>>(),
        );

        let ring = make_ring(my_public_key, &other_keys, |k| k.keypoint.clone());

        SignedMessage {
            message: message.to_string(),
            challenge: sig.challenge.clone(),
            ring: sig
                .ring_responses
                .clone()
                .into_iter()
                .zip(ring)
                .map(|((_, s), p)| (p, s))
                .collect(),
        }
    }

    pub fn verify(&self) -> bool {
        // 1. Verify that the public key attestations are valid
        for (k, _) in self.ring.iter() {
            if !k.validate_attestation() {
                return false;
            }
        }

        // 2. Verify the signature itself
        self.signature().verify(self.message.as_bytes())
    }

    fn signature(&self) -> Signature {
        Signature {
            challenge: self.challenge.clone(),
            ring_responses: self
                .ring
                .iter()
                .map(|(k, s)| (k.keypoint.clone(), s.clone()))
                .collect(),
        }
    }

    pub fn ring(&self) -> impl Iterator<Item = &PublicKey> {
        self.ring.iter().map(|(k, _)| k)
    }
}

// A ZebraSign-signed message in ASCII format looks like this (lines numbered for convenience):

/*
(0)         The following message has been signed using ZebraSign 1.0 Beta:
(1)         """
(2)         Test
(M+2)       """
(M+3)
(M+4)       It was signed by someone with a private key corresponding to one of these fingerprints:
(M+5)
(M+5+1)     Ben Weinstein-Raun <b@w-r.me> Z:$p&B{etV [J3I^)6^#h +4dJaeg6Q. kn-O]{7[tH
(M+5+N)     Joe Camel <cool@tobacco.com> :z6N5iF%x] OZV9Q-p^0C 0c0*l1i0u/ <EgnZFy!44
(M+5+N+1)
(M+5+N+2)   9%Kq+rztr@G/UUZwbP>Z7>&V*av.io+RoI^sPb&o0SSi25=.[ils>3Ss7M8-B97#czy[:{B-4D+003E[Cp^?/zdP/q!aTb+yC+&9/L5.?QFe<N&)li1*NhhYPI[LV.AhV!}*:H2!bn+D4UbI41^@[(bwbQo.H-G&Twp7%IWfs-0069?!aTb+yC+&9/L5.?QFe<N&)li1*NhhYPI[LV.Aiwihg7Yu/b[sVh2J10vI*p]H[S*gekCK-Dmz-%@0n2*}o{}4Ieyfk]hs*-j2Bx<pnD&qD0LlxRmz:?5DJgr002SfwGTuGzdNI{0001ez/oCSBz>R%v}fBfv@Dkx=*PEupvK+z::^HobOkJ[Lr%JJ]puzjY<ELiZ7-&[RpE^E2h^OKLus#2kE%Cj7j%m<z=@>!2OE#</y5?y0002S=*PEupvK+z::^HobOkJ[Lr%JJ]puzjY<ELiZ7-*^4/Af&IVi)R2moE@aE(&{@:wiKNF*Rr0q<6G8k4s6L3zuhs!s8N&9nG(NCOYtp$me1aj.^gt$f7w#4*}O
(M+5+N+3)
(M+5+N+4) To verify this signature, paste this entire message into the ZebraSign app (starting with "The following message" and ending with this line).
*/

// - A fixed prefix (including the 1.0 version number, which should allow us to change aspects of the
//  format in the future)
// - an arbitrary message
// - A fixed explanation of the signature fingerprints
// - A newline-separated list of key identity information (name, email, and fingerprint)
// - The contents of the signature itself (z85 encoded)
// - A fixed suffix explaining how to verify the signature.
//

// The first two lines of the message are always the same.
//
// The last two lines are also always the same.
//
// Before that is a single line (guaranteed by the z85 character set) representing the signature.
//
// And before that there is a blank line, preceeded by some number of nonblank lines, each of which
// contains a name, email, and fingerprint of a key from the ring. None of those fields may contain
// newlines. This section is in turn preceded by a blank line, which lets us determine its boundaries.
//
// Then there's a fixed string separating the signature section from the message section, letting us
// determine where the message ends.
//
// And thus, even though the message can contain any number of (unescaped) newlines (or any utf-8
// text), there is no ambiguity in the message contents, and there is a bijection between our
// signed-message struct and the (syntax of the) ASCII signed message format.
//
// The shortest possible message is 12 lines, with M = N = 1. (Note that the line numbering above
// is zero-indexed, so the length is the last line number plus one.
//
// One other note: z85 itself does not specify padding behavior (in fact it leaves this up to the
// application). We are using the `z85` rust crate, which implements a particular padding strategy.
// This strategy differs from other implementations, and since our z85-encoded signatures aren't
// necessarily divisible into 4-byte chunks, our protocol relies on the padding implementation in
// that specific library. The implementation can be seen here:
// https://github.com/decafbad/z85/blob/ca669a0682b0a559b883f770c93e746f6a7e3ebe/src/internal.rs#L51

const SIGNED_MESSAGE_FIRST_LINE: &str = "The following message has been signed using ZebraSign 1.0 Beta:";
const SIGNED_MESSAGE_SECOND_LINE: &str = "\"\"\"";
const SIGNED_MESSAGE_INFIX_FIRST_LINE: &str = "\"\"\"";
const SIGNED_MESSAGE_INFIX_SECOND_LINE: &str = "";
const SIGNED_MESSAGE_INFIX_THIRD_LINE: &str =
    "It was signed by someone with a private key corresponding to one of these fingerprints:";
const SIGNED_MESSAGE_INFIX_FOURTH_LINE: &str = "";
const SIGNED_MESSAGE_SUFFIX_FIRST_LINE: &str = "";
const SIGNED_MESSAGE_SUFFIX_SECOND_LINE: &str = "To verify this signature, paste this entire message into the ZebraSign app (starting with \"The following message\" and ending with this line).";

impl From<&SignedMessage> for String {
    fn from(m: &SignedMessage) -> String {
        let mut parts = vec![
            SIGNED_MESSAGE_FIRST_LINE.to_string(),
            SIGNED_MESSAGE_SECOND_LINE.to_string(),
        ];
        parts.push(m.message.clone());

        parts.push(SIGNED_MESSAGE_INFIX_FIRST_LINE.to_string());
        parts.push(SIGNED_MESSAGE_INFIX_SECOND_LINE.to_string());
        parts.push(SIGNED_MESSAGE_INFIX_THIRD_LINE.to_string());
        parts.push(SIGNED_MESSAGE_INFIX_FOURTH_LINE.to_string());
        for (k, s) in m.ring.iter() {
            let mut scalar_bytes = vec![];
            s.serialize(&mut scalar_bytes)
                .expect("Failed to serialize scalar into unbounded buffer");
            parts.push(format!(
                "{} <{}> {}",
                k.holder.name(),
                k.holder.email(),
                k.fingerprint()
            ));
        }
        let mut signature_bytes = vec![];
        (m.challenge.clone(), m.ring.clone())
            .serialize(&mut signature_bytes)
            .expect("Failed to serialize scalar into unbounded buffer");
        parts.push("".to_string());
        parts.push(z85::encode(&signature_bytes));
        parts.push(SIGNED_MESSAGE_SUFFIX_FIRST_LINE.to_string());
        parts.push(SIGNED_MESSAGE_SUFFIX_SECOND_LINE.to_string());
        parts.join("\n")
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum SignatureParseError {
    ParseError(),
    NotParseError(i8),
}
use SignatureParseError::*;

impl FromStr for SignedMessage {
    type Err = SignatureParseError;
    /// IMPORTANT NOTE: Success of this method does *not* imply a valid signature, only a
    /// syntactically correct one.
    fn from_str(s: &str) -> Result<SignedMessage, SignatureParseError> {
        // Here's the same signed message from above, reproduced to make it easier to follow the
        // parsing algorithm:
        /*
          (0)         The following message has been signed using ZebraSign 1.0 Beta:
          (1)         """
          (2)         Test
          (M+2)       """
          (M+3)
          (M+4)       It was signed by someone with a private key corresponding to one of these fingerprints:
          (M+5)
          (M+5+1)     Ben Weinstein-Raun <b@w-r.me> Z:$p&B{etV [J3I^)6^#h +4dJaeg6Q. kn-O]{7[tH
          (M+5+N)     Joe Camel <cool@tobacco.com> :z6N5iF%x] OZV9Q-p^0C 0c0*l1i0u/ <EgnZFy!44
          (M+5+N+1)
          (M+5+N+2)   9%Kq+rztr@G/UUZwbP>Z7>&V*av.io+RoI^sPb&o0SSi25=.[ils>3Ss7M8-B97#czy[:{B-4D+003E[Cp^?/zdP/q!aTb+yC+&9/L5.?QFe<N&)li1*NhhYPI[LV.AhV!}*:H2!bn+D4UbI41^@[(bwbQo.H-G&Twp7%IWfs-0069?!aTb+yC+&9/L5.?QFe<N&)li1*NhhYPI[LV.Aiwihg7Yu/b[sVh2J10vI*p]H[S*gekCK-Dmz-%@0n2*}o{}4Ieyfk]hs*-j2Bx<pnD&qD0LlxRmz:?5DJgr002SfwGTuGzdNI{0001ez/oCSBz>R%v}fBfv@Dkx=*PEupvK+z::^HobOkJ[Lr%JJ]puzjY<ELiZ7-&[RpE^E2h^OKLus#2kE%Cj7j%m<z=@>!2OE#</y5?y0002S=*PEupvK+z::^HobOkJ[Lr%JJ]puzjY<ELiZ7-*^4/Af&IVi)R2moE@aE(&{@:wiKNF*Rr0q<6G8k4s6L3zuhs!s8N&9nG(NCOYtp$me1aj.^gt$f7w#4*}O
          (M+5+N+3)
          (M+5+N+4) To verify this signature, paste this entire message into the ZebraSign app (starting with "The following message" and ending with this line).
        */

        // This could have been done with regular expressions or a parser library. I intentionally
        // designed the ASCII format to be fairly simple to reason about; my hope is that this
        // manual parser succeeds at being easier to understand than a BNF-ish or regex-based
        // parser.
        let lines = s.trim().split('\n').collect::<Vec<_>>();
        if lines.len() < 12 {
            // The shortest allowed signed message has a single signer and one (possibly empty)
            // line of message text. This corresponds to M = N = 1, so 1 + 5 + 1 + 4 + 1 = 12 lines.
            return Err(ParseError());
        }

        // Check the fixed prefix (lines 0 and 1)
        if lines[0] != SIGNED_MESSAGE_FIRST_LINE || lines[1] != SIGNED_MESSAGE_SECOND_LINE {
            return Err(ParseError());
        }
        // Check the fixed suffix (lines M+5+N+3 and M+5+N+4; a.k.a. lines.len() - 2 and
        // lines.len() - 1. Then, also check the blank line before the signature data (M+5+N+1 =
        // lines.len() - 3)
        if lines[lines.len() - 1] != SIGNED_MESSAGE_SUFFIX_SECOND_LINE
            || lines[lines.len() - 2] != SIGNED_MESSAGE_SUFFIX_FIRST_LINE
            || !lines[lines.len() - 4].is_empty()
        {
            return Err(ParseError());
        }

        // extract data from the signature line (line M+5+N+2 = lines.len() - 3)
        let signature_bytes = match z85::decode(lines[lines.len() - 3]) {
            Ok(val) => val,
            Err(_) => return Err(ParseError()),
        };

        let (challenge, ring) = match <(Scalar, Vec<(PublicKey, Scalar)>)>::deserialize(
            &mut signature_bytes.as_slice(),
        ) {
            Ok(x) => x,
            Err(_) => return Err(ParseError()),
        };

        // Verify that the ring in the signature data exactly matches the data in the text:
        // (lines M+5+1 through M+5+N; a.k.a. lines.len() - 5 - (N - 1) through lines.len() - 5
        for (i, (signer, _)) in ring.iter().rev().enumerate() {
            if lines[lines.len() - 5 - i]
                != format!(
                    "{} <{}> {}",
                    signer.holder.name(),
                    signer.holder.email(),
                    signer.fingerprint()
                )
            {
                return Err(ParseError());
            }
        }

        // check the fixed lines between the ring info and the message (M+2 through M+5, a.k.a.
        // lines.len() - 5 - ring.len() through lines.len() - 5 - ring.len() - 3)
        if lines[lines.len() - 5 - ring.len()] != SIGNED_MESSAGE_INFIX_FOURTH_LINE
            || lines[lines.len() - 5 - ring.len() - 1] != SIGNED_MESSAGE_INFIX_THIRD_LINE
            || lines[lines.len() - 5 - ring.len() - 2] != SIGNED_MESSAGE_INFIX_SECOND_LINE
            || lines[lines.len() - 5 - ring.len() - 3] != SIGNED_MESSAGE_INFIX_FIRST_LINE
        {
            return Err(ParseError());
        }

        Ok(SignedMessage {
            message: lines[2..lines.len() - 5 - ring.len() - 3].join("\n"),
            challenge,
            ring,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_signatures_work() {
        let message = b"Message";
        let my_key = Scalar::random();
        let signature = Signature::sign(message, my_key.clone(), &[]);
        assert!(
            signature.verify(message),
            "Failed to verify one-key signature"
        );

        let message_a = b"Message A";
        let otherkey_a = RistrettoPoint::random();
        let signature_a = Signature::sign(message_a, my_key.clone(), &[otherkey_a.clone()]);
        assert!(
            signature_a.verify(message_a),
            "Failed to verify two-key signature"
        );

        let message_b = b"Message B";
        let otherkey_b = RistrettoPoint::random();
        let signature_b = Signature::sign(message_b, my_key, &[otherkey_a.clone(), otherkey_b]);
        assert!(
            signature_b.verify(message_b),
            "Failed to verify three-key signature"
        );

        assert!(!Signature {
            ring_responses: signature_a.ring_responses.clone(),
            challenge: signature_b.challenge.clone(),
        }
        .verify(message_b));
        assert!(!signature_b.verify(message_a));
        assert!(!Signature {
            challenge: signature_a.challenge.clone(),
            ring_responses: signature_b.ring_responses.clone(),
        }
        .verify(message_b));
    }

    #[test]
    fn full_signatures_work() {
        let message = "SPARTACVSSVM";
        let my_email = BoringAscii::from_bytes(b"zebra@example.com").unwrap();
        let my_name = "ZebraSign";
        let my_id = Identity::new(my_name, &my_email).unwrap();
        let my_key = PrivateKey::new(my_id.clone());

        let other_email = BoringAscii::from_bytes(b"notzebra@example.com").unwrap();
        let other_name = "Gaius";
        let other_id = Identity::new(other_name, &other_email).unwrap();
        let other_key = PrivateKey::new(other_id.clone());
        let other_public = other_key.public();

        let mut signed = SignedMessage::sign(message, &my_key, &[other_public]);
        assert!(signed.verify());

        signed.message = String::new();
        signed.message = signed.message.clone() + "SPARTACVSEST";
        assert!(!signed.verify());
    }

    #[test]
    fn export_and_import_work() {
        let my_email = BoringAscii::from_bytes(b"zebra@example.com").unwrap();
        let my_name = "ZebraSign";
        let my_id = Identity::new(my_name, &my_email).unwrap();
        let my_key = PrivateKey::new(my_id.clone());
        let export = String::from(my_key.public());
        let import = PublicKey::from_str(&export);
        let PublicKey {
            ref holder,
            ref version,
            ref keypoint,
            ref holder_attestation,
        } = import.unwrap();

        assert!(holder == &my_key.holder);
        assert!(version == &my_key.public().version);
        assert!(keypoint == &my_key.public().keypoint);
        assert!(holder_attestation == holder_attestation);
    }

    #[test]
    fn serialization_of_signed_message() {
        let message = "SPARTACVSSVM";
        let my_email = BoringAscii::from_bytes(b"zebra@example.com").unwrap();
        let my_name = "ZebraSign";
        let my_id = Identity::new(my_name, &my_email).unwrap();
        let my_key = PrivateKey::new(my_id.clone());

        let other_email = BoringAscii::from_bytes(b"notzebra@example.com").unwrap();
        let other_name = "Gaius";
        let other_id = Identity::new(other_name, &other_email).unwrap();
        let other_key = PrivateKey::new(other_id.clone());
        let other_public = other_key.public();

        let signed = SignedMessage::sign(message, &my_key, &[other_public]);
        let signed_text = String::from(&signed);
        eprintln!("{}", signed_text);
        eprintln!(
            "{}",
            String::from(&SignedMessage::from_str(&signed_text).unwrap())
        );
        assert!(SignedMessage::from_str(&signed_text) == Ok(signed));
    }
}
