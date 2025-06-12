use crate::{error::Error, sql_read_bytes::SqlReadBytes, ColumnData, numeric::Numeric};

pub(crate) async fn decode<R>(src: &mut R, len: u8) -> crate::Result<ColumnData<'static>>
where
    R: SqlReadBytes + Unpin,
{
    let res = match len {
        0 => ColumnData::Numeric(None),
        4 => {
            let value = src.read_i32_le().await? as i128;
            ColumnData::Numeric(Some(Numeric::new_with_scale(value, 4)))
        },
        8 => {
            let high = src.read_i32_le().await? as i64;
            let low = src.read_u32_le().await? as i64;
            let value = ((high << 32) + low) as i128;
            ColumnData::Numeric(Some(Numeric::new_with_scale(value, 4)))
        },
        _ => return Err(Error::Protocol(format!("money: length of {} is invalid", len).into()))
    };
    Ok(res)
}
