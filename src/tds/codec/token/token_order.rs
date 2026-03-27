use crate::SqlReadBytes;
use futures_util::io::AsyncReadExt;

#[allow(dead_code)]
#[derive(Debug)]
pub struct TokenOrder {
    pub(crate) column_indexes: Vec<u16>,
}

impl TokenOrder {
    pub(crate) async fn decode<R>(src: &mut R) -> crate::Result<Self>
    where
        R: SqlReadBytes + Unpin,
    {
        let byte_len = src.read_u16_le().await? as usize;

        let mut buf = vec![0u8; byte_len];
        src.read_exact(&mut buf).await?;

        let column_indexes: Vec<u16> = buf
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();

        Ok(TokenOrder { column_indexes })
    }
}
