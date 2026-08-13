//! The XML containers
use super::codec::Encode;
use bytes::{BufMut, BytesMut};
use std::borrow::BorrowMut;
use std::sync::Arc;

/// Provides information of the location for the schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmlSchema {
    db_name: String,
    owner: String,
    collection: String,
}

impl XmlSchema {
    pub(crate) fn new(
        db_name: impl ToString,
        owner: impl ToString,
        collection: impl ToString,
    ) -> Self {
        Self {
            db_name: db_name.to_string(),
            owner: owner.to_string(),
            collection: collection.to_string(),
        }
    }

    /// Specifies the name of the database where the schema collection is defined.
    pub fn db_name(&self) -> &str {
        &self.db_name
    }

    /// Specifies the name of the relational schema containing the schema collection.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Specifies the name of the XML schema collection to which the type is
    /// bound.
    pub fn collection(&self) -> &str {
        &self.collection
    }
}

/// A representation of XML data in TDS. Holds the data as a UTF-8 string and
/// and optional information about the schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmlData {
    data: String,
    schema: Option<Arc<XmlSchema>>,
}

impl XmlData {
    /// Create a new XmlData with the given string. Validation of the XML data
    /// happens in the database.
    pub fn new(data: impl ToString) -> Self {
        Self {
            data: data.to_string(),
            schema: None,
        }
    }

    pub(crate) fn set_schema(&mut self, schema: Arc<XmlSchema>) {
        self.schema = Some(schema);
    }

    /// Returns information about the schema of the XML file, if existing.
    #[allow(clippy::option_as_ref_deref)]
    pub fn schema(&self) -> Option<&XmlSchema> {
        self.schema.as_ref().map(|s| &**s)
    }

    /// Takes the XML string out from the struct.
    pub fn into_string(self) -> String {
        self.data
    }

    pub(crate) fn into_nvarchar_string(mut self) -> String {
        if let Some(range) = encoding_declaration_range(&self.data) {
            self.data.replace_range(range, "");
        }

        self.data
    }
}

impl std::fmt::Display for XmlData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.data)
    }
}

impl AsRef<str> for XmlData {
    fn as_ref(&self) -> &str {
        self.data.as_ref()
    }
}

impl Encode<BytesMut> for XmlData {
    fn encode(self, dst: &mut BytesMut) -> crate::Result<()> {
        // unknown size
        dst.put_u64_le(0xfffffffffffffffe_u64);

        // first blob
        let mut length = 0u32;
        let len_pos = dst.len();

        // writing the length later
        dst.put_u32_le(length);

        for chr in self.data.encode_utf16() {
            length += 1;
            dst.put_u16_le(chr);
        }

        // PLP_TERMINATOR, no next blobs
        dst.put_u32_le(0);

        let dst: &mut [u8] = dst.borrow_mut();
        let mut dst = &mut dst[len_pos..];
        dst.put_u32_le(length * 2);

        Ok(())
    }
}

fn encoding_declaration_range(data: &str) -> Option<std::ops::Range<usize>> {
    let declaration_start = usize::from(data.starts_with('\u{feff}')) * '\u{feff}'.len_utf8();
    let declaration = &data[declaration_start..];
    let declaration = declaration.strip_prefix("<?xml")?;
    let first = declaration.as_bytes().first()?;
    if !first.is_ascii_whitespace() {
        return None;
    }

    let declaration_end = declaration.find("?>")?;
    let attributes = &declaration[..declaration_end];
    let bytes = attributes.as_bytes();

    for start in 0..bytes.len().saturating_sub(b"encoding".len() - 1) {
        if !bytes[start..].starts_with(b"encoding") {
            continue;
        }
        if start > 0 && !bytes[start - 1].is_ascii_whitespace() {
            continue;
        }

        let mut position = start + b"encoding".len();
        while position < bytes.len() && bytes[position].is_ascii_whitespace() {
            position += 1;
        }
        if bytes.get(position) != Some(&b'=') {
            continue;
        }
        position += 1;
        while position < bytes.len() && bytes[position].is_ascii_whitespace() {
            position += 1;
        }

        let Some(&quote @ (b'\'' | b'"')) = bytes.get(position) else {
            continue;
        };
        position += 1;
        let value_end = bytes[position..].iter().position(|byte| *byte == quote)?;

        let mut remove_start = start;
        while remove_start > 0 && bytes[remove_start - 1].is_ascii_whitespace() {
            remove_start -= 1;
        }
        let remove_end = position + value_end + 1;
        return Some(
            declaration_start + "<?xml".len() + remove_start
                ..declaration_start + "<?xml".len() + remove_end,
        );
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_encoding_from_xml_declaration_for_nvarchar() {
        for (xml, expected) in [
            (
                r#"<?xml version="1.0" encoding="UTF-8"?><root/>"#,
                r#"<?xml version="1.0"?><root/>"#,
            ),
            (
                r#"<?xml version='1.0' encoding = 'windows-1252' standalone='yes'?><root/>"#,
                r#"<?xml version='1.0' standalone='yes'?><root/>"#,
            ),
        ] {
            assert_eq!(expected, XmlData::new(xml).into_nvarchar_string());
        }
    }

    #[test]
    fn leaves_non_declaration_content_unchanged() {
        for xml in [
            "<root encoding=\"UTF-8\"/>",
            r#"<?xml-stylesheet encoding="UTF-8"?><root/>"#,
            r#"<?xml version="1.0"?><root/>"#,
        ] {
            assert_eq!(xml, XmlData::new(xml).into_nvarchar_string());
        }
    }
}
