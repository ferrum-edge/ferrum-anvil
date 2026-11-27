//! LAB-ONLY SOAP signing material: the X.509 identities AUTH-030 signs with
//! (through Anvil's own WS-Security signer) and the lab's SAML identity
//! provider for AUTH-031.
//!
//! AUTH-030 envelopes are signed by Anvil (`anvil_auth::wsse`, exclusive
//! canonicalization and RSA-SHA256 over Body and Timestamp) with the
//! throwaway `soap-signer` key the gateway route trusts, or the `soap-rogue`
//! key it does not; the gateway's own, independent canonicalizer and
//! verifier is the cross-check. Only the SAML assertions of AUTH-031 are
//! still signed here, playing the identity provider, with two audited tools
//! already present on the host:
//!
//! * `xmllint --exc-c14n` (libxml2's Exclusive XML Canonicalization 1.0,
//!   the same implementation xmlsec1 uses) canonicalizes the assertion and
//!   its `SignedInfo`;
//! * `openssl` generates throwaway RSA-2048 keys with self-signed
//!   certificates and computes RSA-SHA256 signatures.
//!
//! Keys and certificates are generated fresh under the git-ignored run
//! directory at every lab start and are never trusted outside the lab.
//! Each referenced element is written in a standalone form that declares
//! exactly the namespaces it visibly uses, so its exclusive canonical form is
//! identical to the in-context one the gateway computes.

use anvil_domain::{SecondsFormat, Timestamp};
use anyhow::{Context, Result, bail};
use base64::Engine as _;
use sha2::Digest;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const DS_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
pub const SAML_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

/// The external tools the lab uses, with the versions they reported.
/// `openssl` is required (it creates the keys and certificates the gateway
/// config references); without `xmllint` the lab cannot issue SAML
/// assertions and AUTH-031 is skipped with that reason.
#[derive(Clone, Debug)]
pub struct SignerTools {
    pub xmllint: Option<String>,
    pub openssl: String,
    pub versions: String,
}

fn find_on_path(name: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).map(|d| d.join(name)).find(|p| p.is_file()).map(|p| p.display().to_string())
}

fn version(bin: &str, arg: &str) -> String {
    Command::new(bin)
        .arg(arg)
        .output()
        .ok()
        .map(|o| {
            let t = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
            t.lines().next().unwrap_or("").trim().to_string()
        })
        .unwrap_or_default()
}

impl SignerTools {
    pub fn locate() -> std::result::Result<Self, String> {
        let openssl = find_on_path("openssl").ok_or("openssl is not installed on this host")?;
        let xmllint = find_on_path("xmllint");
        let versions = format!(
            "{}; {}",
            xmllint.as_deref().map(|x| version(x, "--version")).unwrap_or_else(|| "xmllint: not installed".into()),
            version(&openssl, "version")
        );
        Ok(SignerTools { xmllint, openssl, versions })
    }

    /// Why the lab cannot issue signed SAML assertions on this host, if it
    /// cannot.
    pub fn signing_unavailable(&self) -> Option<String> {
        self.xmllint.is_none().then(|| {
            "xmllint (libxml2 Exclusive XML Canonicalization, the audited canonicalizer the lab's SAML identity provider needs) is not installed on this host".to_string()
        })
    }

    /// libxml2 Exclusive XML Canonicalization 1.0 (without comments).
    pub fn exc_c14n(&self, dir: &Path, xml: &str) -> Result<String> {
        static N: AtomicU64 = AtomicU64::new(0);
        let f = dir.join(format!("c14n-{}.xml", N.fetch_add(1, Ordering::Relaxed)));
        let Some(xmllint) = &self.xmllint else { bail!("xmllint is not installed") };
        std::fs::write(&f, xml)?;
        let out = Command::new(xmllint).arg("--exc-c14n").arg(&f).output().context("running xmllint")?;
        std::fs::remove_file(&f).ok();
        if !out.status.success() {
            bail!("xmllint --exc-c14n failed: {}", String::from_utf8_lossy(&out.stderr));
        }
        Ok(String::from_utf8(out.stdout)?)
    }
}

/// A throwaway RSA-2048 signing identity (self-signed certificate).
#[derive(Clone, Debug)]
pub struct Signer {
    pub key_path: PathBuf,
    pub cert_path: PathBuf,
    /// Base64 DER of the certificate (for `ds:X509Certificate`).
    pub cert_b64: String,
}

impl Signer {
    pub fn generate(tools: &SignerTools, dir: &Path, name: &str, cn: &str) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        let key_path = dir.join(format!("{name}.key"));
        let cert_path = dir.join(format!("{name}.pem"));
        let out = Command::new(&tools.openssl)
            .args(["req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes", "-days", "2", "-subj"])
            .arg(format!("/O=Ferrum Anvil Gateway Lab/CN={cn}"))
            .arg("-keyout")
            .arg(&key_path)
            .arg("-out")
            .arg(&cert_path)
            .output()
            .context("running openssl req")?;
        if !out.status.success() {
            bail!("openssl req failed: {}", String::from_utf8_lossy(&out.stderr));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
        }
        let pem = std::fs::read_to_string(&cert_path)?;
        let cert_b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        Ok(Signer { key_path, cert_path, cert_b64 })
    }

    /// The private key and the certificate as PEM, as a user would paste
    /// them into Anvil's WS-Security signature settings.
    pub fn pem(&self) -> Result<(String, String)> {
        Ok((std::fs::read_to_string(&self.key_path)?, std::fs::read_to_string(&self.cert_path)?))
    }

    /// RSA PKCS#1 v1.5 SHA-256 signature (base64).
    fn sign(&self, tools: &SignerTools, dir: &Path, data: &str) -> Result<String> {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let input = dir.join(format!("signed-info-{n}.xml"));
        let sig = dir.join(format!("signed-info-{n}.sig"));
        std::fs::write(&input, data)?;
        let out = Command::new(&tools.openssl)
            .args(["dgst", "-sha256", "-sign"])
            .arg(&self.key_path)
            .arg("-out")
            .arg(&sig)
            .arg(&input)
            .output()
            .context("running openssl dgst")?;
        let bytes = std::fs::read(&sig);
        std::fs::remove_file(&input).ok();
        std::fs::remove_file(&sig).ok();
        if !out.status.success() {
            bail!("openssl dgst failed: {}", String::from_utf8_lossy(&out.stderr));
        }
        Ok(base64::engine::general_purpose::STANDARD.encode(bytes?))
    }
}

fn b64_sha256(s: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(s.as_bytes()))
}

fn ts(t: Timestamp) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn reference(uri: &str, enveloped: bool, digest: &str) -> String {
    let env = if enveloped { format!(r#"<ds:Transform Algorithm="{ENVELOPED}"/>"#) } else { String::new() };
    format!(
        r##"<ds:Reference URI="#{uri}"><ds:Transforms>{env}<ds:Transform Algorithm="{EXC_C14N}"/></ds:Transforms><ds:DigestMethod Algorithm="{SHA256}"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference>"##
    )
}

/// `(SignedInfo as written in context, standalone form for canonicalization)`.
fn signed_info(references: &str) -> (String, String) {
    let inner = format!(r#"<ds:CanonicalizationMethod Algorithm="{EXC_C14N}"/><ds:SignatureMethod Algorithm="{RSA_SHA256}"/>{references}"#);
    (format!("<ds:SignedInfo>{inner}</ds:SignedInfo>"), format!(r#"<ds:SignedInfo xmlns:ds="{DS_NS}">{inner}</ds:SignedInfo>"#))
}

/// Everything needed to sign in one place.
pub struct SoapSigning {
    pub tools: SignerTools,
    pub dir: PathBuf,
    /// Trusted by the X.509 route (AUTH-030 signs with it through Anvil).
    pub soap_signer: Signer,
    /// Trusted by the SAML route (the lab's SAML identity provider).
    pub saml_idp: Signer,
    /// Trusted by nothing.
    pub rogue: Signer,
}

impl SoapSigning {
    pub fn setup(dir: &Path) -> std::result::Result<Self, String> {
        let tools = SignerTools::locate()?;
        let mk = |name: &str, cn: &str| Signer::generate(&tools, dir, name, cn).map_err(|e| format!("{e:#}"));
        Ok(SoapSigning {
            soap_signer: mk("soap-signer", "anvil-lab-soap-signer")?,
            saml_idp: mk("saml-idp", "anvil-lab-saml-idp")?,
            rogue: mk("soap-rogue", "anvil-lab-soap-rogue")?,
            dir: dir.to_path_buf(),
            tools,
        })
    }

    /// A signed SAML 2.0 bearer assertion (enveloped signature over the
    /// assertion, exclusive C14N, RSA-SHA256) — what an identity provider
    /// would issue.
    pub fn saml_assertion(&self, signer: &Signer, a: &SamlSpec) -> Result<String> {
        static N: AtomicU64 = AtomicU64::new(1);
        let id = format!("_anvil-lab-{}-{}", Timestamp::now().unix_micros(), N.fetch_add(1, Ordering::Relaxed));
        let (nb, noa) = (ts(a.not_before), ts(a.not_on_or_after));
        let issue = ts(a.not_before);
        let issuer = format!("<saml:Issuer>{}</saml:Issuer>", a.issuer);
        let rest = format!(
            r#"<saml:Subject><saml:NameID>{}</saml:NameID><saml:SubjectConfirmation Method="{BEARER}"><saml:SubjectConfirmationData NotOnOrAfter="{noa}" Recipient="{}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{nb}" NotOnOrAfter="{noa}"><saml:AudienceRestriction><saml:Audience>{}</saml:Audience></saml:AudienceRestriction></saml:Conditions>"#,
            a.name_id, a.recipient, a.audience
        );
        let open = format!(r#"<saml:Assertion xmlns:saml="{SAML_NS}" ID="{id}" IssueInstant="{issue}" Version="2.0">"#);
        let unsigned = format!("{open}{issuer}{rest}</saml:Assertion>");
        let digest = b64_sha256(&self.tools.exc_c14n(&self.dir, &unsigned)?);
        let (si_ctx, si_alone) = signed_info(&reference(&id, true, &digest));
        let sig_value = signer.sign(&self.tools, &self.dir, &self.tools.exc_c14n(&self.dir, &si_alone)?)?;
        let signature = format!(
            r#"<ds:Signature xmlns:ds="{DS_NS}">{si_ctx}<ds:SignatureValue>{sig_value}</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>"#,
            signer.cert_b64
        );
        Ok(format!("{open}{issuer}{signature}{rest}</saml:Assertion>"))
    }
}

/// Assertion content (the lab is the identity provider).
#[derive(Clone, Debug)]
pub struct SamlSpec {
    pub issuer: String,
    pub name_id: String,
    pub audience: String,
    pub recipient: String,
    pub not_before: Timestamp,
    pub not_on_or_after: Timestamp,
}
