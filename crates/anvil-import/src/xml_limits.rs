//! The pre-parse XML scan, shared with every other crate that parses XML
//! (see `anvil-xml-limits`). WSDL imports parse with DTDs refused, as the
//! scan requires.

pub(crate) use anvil_xml_limits::{XmlLimitExceeded, XmlLimits, check_xml_limits};
