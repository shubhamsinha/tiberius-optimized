use crate::{sql_read_bytes::SqlReadBytes, ColumnData};
use futures_util::io::AsyncReadExt;

pub(crate) async fn decode<R>(src: &mut R) -> crate::Result<ColumnData<'static>>
where
    R: SqlReadBytes + Unpin,
{
    let ptr_len = src.read_u8().await? as usize;

    if ptr_len == 0 {
        return Ok(ColumnData::Binary(None));
    }

    let mut skip = vec![0u8; ptr_len];
    src.read_exact(&mut skip).await?;

    src.read_i32_le().await?;
    src.read_u32_le().await?;

    let len = src.read_u32_le().await? as usize;
    let mut buf = vec![0u8; len];
    src.read_exact(&mut buf).await?;

    Ok(ColumnData::Binary(Some(buf.into())))
}
