use crate::{error::Error, sql_read_bytes::SqlReadBytes, tds::Collation, ColumnData};
use futures_util::io::AsyncReadExt;

pub(crate) async fn decode<R>(
    src: &mut R,
    collation: Option<Collation>,
) -> crate::Result<ColumnData<'static>>
where
    R: SqlReadBytes + Unpin,
{
    let ptr_len = src.read_u8().await? as usize;

    if ptr_len == 0 {
        return Ok(ColumnData::String(None));
    }

    let mut skip = vec![0u8; ptr_len];
    src.read_exact(&mut skip).await?;

    src.read_i32_le().await?;
    src.read_u32_le().await?;

    let text = match collation {
        Some(collation) => {
            let encoder = collation.encoding()?;
            let text_len = src.read_u32_le().await? as usize;
            let mut buf = vec![0u8; text_len];
            src.read_exact(&mut buf).await?;

            encoder
                .decode_without_bom_handling_and_without_replacement(buf.as_ref())
                .ok_or_else(|| Error::Encoding("invalid sequence".into()))?
                .to_string()
        }
        None => {
            let byte_len = src.read_u32_le().await? as usize;
            let mut buf = vec![0u8; byte_len];
            src.read_exact(&mut buf).await?;

            let u16_buf: Vec<u16> = buf
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect();

            String::from_utf16(&u16_buf)?
        }
    };

    Ok(ColumnData::String(Some(text.into())))
}
