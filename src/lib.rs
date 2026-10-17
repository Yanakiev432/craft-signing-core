//! Reusable contracts; production cryptography remains in format/provider adapters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provider { WindowsCng, MacosKeychain, Pkcs11, Pkcs12, Remote }
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityRef { pub provider: Provider, pub id: String }
impl IdentityRef {
    pub fn parse(s: &str) -> Result<Self, &'static str> {
        let (p,id)=s.split_once(':').ok_or("missing namespace")?;
        if id.is_empty() || id.trim()!=id || id.chars().any(char::is_control) {return Err("invalid identifier");}
        let provider=match p {
            "windows"=>Provider::WindowsCng, "keychain"=>Provider::MacosKeychain,
            "pkcs11"=>Provider::Pkcs11, "pkcs12"=>Provider::Pkcs12,
            "remote"=>Provider::Remote, _=>return Err("unknown provider")
        };
        Ok(Self {provider,id:id.to_owned()})
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Digest { Sha256, Sha384, Sha512 }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict { Valid, Invalid, Unknown }
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verification {
    pub integrity: Verdict,
    pub chain_trust: Verdict,
    pub revocation: Verdict,
    pub timestamp: Verdict,
    pub details: Vec<String>,
}
pub trait SigningProvider {
    fn list_identities(&self) -> Result<Vec<IdentityRef>, String>;
    fn sign_digest(&self, id: &IdentityRef, algorithm: Digest, digest: &[u8]) -> Result<Vec<u8>, String>;
}
pub trait DocumentSignatureAdapter {
    fn format(&self) -> &'static str;
    fn sign(&self, original: &[u8], id: &IdentityRef) -> Result<Vec<u8>, String>;
    fn verify(&self, document: &[u8]) -> Result<Verification, String>;
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn identity_validation() {
        assert_eq!(IdentityRef::parse("windows:abc").unwrap().provider,Provider::WindowsCng);
        for bad in ["","windows:","unknown:abc","windows: abc","windows:a\nb"] {
            assert!(IdentityRef::parse(bad).is_err());
        }
    }
    #[test] fn trust_is_independent() {
        let result=Verification { integrity:Verdict::Valid, chain_trust:Verdict::Unknown,
            revocation:Verdict::Unknown,timestamp:Verdict::Unknown,details:vec![] };
        assert_ne!(result.integrity,result.chain_trust);
    }
}
