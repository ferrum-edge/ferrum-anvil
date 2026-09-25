//! LAB-ONLY signed SOAP fixtures (AUTH-030 X.509 signature, AUTH-031 SAML).
//!
//! Anvil does not sign XML: an XML-DSig signer needs an audited
//! canonicalization implementation, and Anvil ships none (the WS-Security
//! editor offers UsernameToken and a *user-supplied* SAML assertion only).
//! The lab therefore plays the external signer and the SAML identity
//! provider, using two audited tools already present on the host — never a
//! hand-written canonicalizer:
//!
//! * `xmllint --exc-c14n` (libxml2's Exclusive XML Canonicalization 1.0,
//!   the same implementation xmlsec1 uses) canonicalizes every signed
//!   element and every `SignedInfo`;
//! * `openssl` generates throwaway RSA-2048 keys with self-signed
//!   certificates and computes RSA-SHA256 signatures.
//!
//! Keys and certificates are generated fresh under the git-ignored run
//! directory at every lab start and are never trusted outside the lab.
//! Each referenced element is written in a standalone form that declares
//! exactly the namespaces it visibly uses, so its exclusive canonical form is
//! identical to the in-context one the gateway computes; the gateway's own
//! (independent) canonicalizer accepting the result is the cross-check.

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use sha2::Digest;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

pub const SOAP11_NS: &str = "http://schemas.xmlsoap.org/soap/envelope/";
pub const WSSE_NS: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
pub const WSU_NS: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
const DS_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
pub const SAML_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

/// The external tools the signer uses, with the versions they reported.
/// `openssl` is required (it creates the certificates the gateway config
/// references); without `xmllint` nothing can be signed and the signed-XML
/// scenarios are skipped with that reason.
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

    /// Why XML cannot be signed on this host, if it cannot.
    pub fn signing_unavailable(&self) -> Option<String> {
        self.xmllint.is_none().then(|| {
            "xmllint (libxml2 Exclusive XML Canonicalization, the audited canonicalizer the lab signer needs) is not installed on this host; Anvil itself never signs XML".to_string()
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

fn ts(t: DateTime<Utc>) -> String {
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
    /// Trusted by the X.509 route.
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

    /// A SOAP 1.1 envelope whose Body and Timestamp are signed (exclusive
    /// C14N, RSA-SHA256) by `signer`, certificate in `KeyInfo/X509Data`.
    pub fn signed_envelope(&self, signer: &Signer, payload: &str, now: DateTime<Utc>, ttl_secs: i64) -> Result<String> {
        let (created, expires) = (ts(now), ts(now + Duration::seconds(ttl_secs)));
        let ts_inner = format!(r#"<wsu:Created>{created}</wsu:Created><wsu:Expires>{expires}</wsu:Expires>"#);
        let body_inner = format!(r#"<m:Ping xmlns:m="urn:anvil:lab:soap">{payload}</m:Ping>"#);
        // In-context forms (namespaces inherited from Envelope) and their
        // standalone equivalents for canonicalization.
        let ts_ctx = format!(r#"<wsu:Timestamp wsu:Id="TS-1">{ts_inner}</wsu:Timestamp>"#);
        let ts_alone = format!(r#"<wsu:Timestamp xmlns:wsu="{WSU_NS}" wsu:Id="TS-1">{ts_inner}</wsu:Timestamp>"#);
        let body_ctx = format!(r#"<soap:Body wsu:Id="Body-1">{body_inner}</soap:Body>"#);
        let body_alone = format!(r#"<soap:Body xmlns:soap="{SOAP11_NS}" xmlns:wsu="{WSU_NS}" wsu:Id="Body-1">{body_inner}</soap:Body>"#);
        let d_ts = b64_sha256(&self.tools.exc_c14n(&self.dir, &ts_alone)?);
        let d_body = b64_sha256(&self.tools.exc_c14n(&self.dir, &body_alone)?);
        let (si_ctx, si_alone) = signed_info(&format!("{}{}", reference("TS-1", false, &d_ts), reference("Body-1", false, &d_body)));
        let sig_value = signer.sign(&self.tools, &self.dir, &self.tools.exc_c14n(&self.dir, &si_alone)?)?;
        let signature = format!(
            r#"<ds:Signature xmlns:ds="{DS_NS}">{si_ctx}<ds:SignatureValue>{sig_value}</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>"#,
            signer.cert_b64
        );
        Ok(format!(
            r#"<soap:Envelope xmlns:soap="{SOAP11_NS}" xmlns:wsu="{WSU_NS}"><soap:Header><wsse:Security xmlns:wsse="{WSSE_NS}">{ts_ctx}{signature}</wsse:Security></soap:Header>{body_ctx}</soap:Envelope>"#
        ))
    }

    /// A signed SAML 2.0 bearer assertion (enveloped signature over the
    /// assertion, exclusive C14N, RSA-SHA256) — what an identity provider
    /// would issue. `window` = (NotBefore, NotOnOrAfter).
    pub fn saml_assertion(&self, signer: &Signer, a: &SamlSpec) -> Result<String> {
        static N: AtomicU64 = AtomicU64::new(1);
        let id = format!("_anvil-lab-{}-{}", Utc::now().timestamp_micros(), N.fetch_add(1, Ordering::Relaxed));
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
    pub not_before: DateTime<Utc>,
    pub not_on_or_after: DateTime<Utc>,
}
