use futures_util::io::{AsyncRead, AsyncWrite};
use names::{Generator, Name};
use once_cell::sync::Lazy;
use std::cell::RefCell;
use std::env;
use std::sync::Once;
use tiberius::{xml::XmlData, BulkLoadOptions, IntoSql, Result, TokenRow};

#[cfg(all(feature = "tds73", feature = "chrono"))]
use chrono::{DateTime, NaiveDate, NaiveDateTime};

use runtimes_macro::test_on_runtimes;

// This is used in the testing macro :)
#[allow(dead_code)]
static LOGGER_SETUP: Once = Once::new();

static CONN_STR: Lazy<String> = Lazy::new(|| {
    env::var("TIBERIUS_TEST_CONNECTION_STRING").unwrap_or_else(|_| {
        "server=tcp:localhost,1433;IntegratedSecurity=true;TrustServerCertificate=true".to_owned()
    })
});

thread_local! {
    static NAMES: RefCell<Option<Generator<'static>>> =
    RefCell::new(None);
}

async fn random_table() -> String {
    NAMES.with(|maybe_generator| {
        maybe_generator
            .borrow_mut()
            .get_or_insert_with(|| Generator::with_naming(Name::Plain))
            .next()
            .unwrap()
            .replace('-', "")
    })
}

macro_rules! test_bulk_type {
    ($name:ident($sql_type:literal, $total_generated:expr, $generator:expr)) => {
        paste::item! {
            #[test_on_runtimes]
            async fn [< bulk_load_optional_ $name >]<S>(mut conn: tiberius::Client<S>) -> Result<()>
            where
                S: AsyncRead + AsyncWrite + Unpin + Send,
            {
                let table = format!("##{}", random_table().await);

                conn.execute(
                    &format!(
                        "CREATE TABLE {} (id INT IDENTITY PRIMARY KEY, content {} NULL)",
                        table,
                        $sql_type,
                    ),
                    &[],
                )
                    .await?;

                let mut req = conn.bulk_insert(&table).await?;

                for i in $generator {
                    let mut row = TokenRow::new();
                    row.push(i.into_sql());
                    req.send(row).await?;
                }

                let res = req.finalize().await?;

                assert_eq!($total_generated, res.total());

                Ok(())
            }

            #[test_on_runtimes]
            async fn [< bulk_load_required_ $name >]<S>(mut conn: tiberius::Client<S>) -> Result<()>
            where
                S: AsyncRead + AsyncWrite + Unpin + Send,
            {
                let table = format!("##{}", random_table().await);

                conn.execute(
                    &format!(
                        "CREATE TABLE {} (id INT IDENTITY PRIMARY KEY, content {} NOT NULL)",
                        table,
                        $sql_type
                    ),
                    &[],
                )
                    .await?;

                let mut req = conn.bulk_insert(&table).await?;

                for i in $generator {
                    let mut row = TokenRow::new();
                    row.push(i.into_sql());
                    req.send(row).await?;
                }

                let res = req.finalize().await?;

                assert_eq!($total_generated, res.total());

                Ok(())
            }
        }
    };
}

test_bulk_type!(tinyint("TINYINT", 256, 0..=255u8));
test_bulk_type!(smallint("SMALLINT", 2000, 0..2000i16));
test_bulk_type!(int("INT", 2000, 0..2000i32));
test_bulk_type!(bigint("BIGINT", 2000, 0..2000i64));

test_bulk_type!(empty_varchar(
    "VARCHAR(MAX)",
    100,
    vec![""; 100].into_iter()
));
test_bulk_type!(empty_nvarchar(
    "NVARCHAR(MAX)",
    100,
    vec![""; 100].into_iter()
));
test_bulk_type!(empty_varbinary(
    "VARBINARY(MAX)",
    100,
    vec![b""; 100].into_iter()
));

test_bulk_type!(real(
    "REAL",
    1000,
    vec![std::f32::consts::PI; 1000].into_iter()
));

test_bulk_type!(float(
    "FLOAT",
    1000,
    vec![std::f64::consts::PI; 1000].into_iter()
));

#[test_on_runtimes]
async fn bulk_load_quoted_identifiers<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let table = format!("##{}", random_table().await);

    conn.execute(
        &format!(
            "CREATE TABLE {} (\
                [normal] INT NOT NULL, \
                [order] INT NOT NULL, \
                [customer name] INT NOT NULL, \
                [a]]b] INT NOT NULL, \
                [顧客名] INT NOT NULL\
            )",
            table
        ),
        &[],
    )
    .await?;

    let mut req = conn.bulk_insert(&table).await?;
    let mut row = TokenRow::new();
    for value in 1i32..=5 {
        row.push(value.into_sql());
    }
    req.send(row).await?;

    let result = req.finalize().await?;
    assert_eq!(1, result.total());

    let row = conn
        .query(
            &format!(
                "SELECT [normal], [order], [customer name], [a]]b], [顧客名] FROM {}",
                table
            ),
            &[],
        )
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some(1), row.get::<i32, _>("normal"));
    assert_eq!(Some(2), row.get::<i32, _>("order"));
    assert_eq!(Some(3), row.get::<i32, _>("customer name"));
    assert_eq!(Some(4), row.get::<i32, _>("a]b"));
    assert_eq!(Some(5), row.get::<i32, _>("顧客名"));

    Ok(())
}

#[cfg(all(feature = "tds73", feature = "chrono"))]
#[test_on_runtimes]
async fn bulk_load_date_round_trip<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let table = format!("##{}", random_table().await);
    conn.execute(
        &format!(
            "CREATE TABLE {} (id INT IDENTITY, content DATE NULL)",
            table
        ),
        &[],
    )
    .await?;

    let minimum = NaiveDate::from_ymd_opt(1, 1, 1).unwrap();
    let maximum = NaiveDate::from_ymd_opt(9999, 12, 31).unwrap();
    let values = [
        Some(minimum),
        Some(NaiveDate::from_ymd_opt(2024, 2, 29).unwrap()),
        Some(maximum),
        None,
    ];
    let mut request = conn.bulk_insert(&table).await?;

    for value in values {
        let mut row = TokenRow::new();
        row.push(value.into_sql());
        request.send(row).await?;
    }

    assert_eq!(4, request.finalize().await?.total());

    let rows = conn
        .query(&format!("SELECT content FROM {} ORDER BY id", table), &[])
        .await?
        .into_first_result()
        .await?;

    assert_eq!(Some(minimum), rows[0].get(0));
    assert_eq!(
        Some(NaiveDate::from_ymd_opt(2024, 2, 29).unwrap()),
        rows[1].get(0)
    );
    assert_eq!(Some(maximum), rows[2].get(0));
    assert_eq!(None, rows[3].get::<NaiveDate, _>(0));

    Ok(())
}

#[test_on_runtimes]
async fn bulk_load_xml_round_trip<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let table = format!("##{}", random_table().await);
    conn.execute(
        &format!(
            "CREATE TABLE {} (id INT IDENTITY, before_value INT, content XML NULL, after_value INT)",
            table
        ),
        &[],
    )
    .await?;

    let unicode = XmlData::new("<root>雪😀</root>");
    let declaration = XmlData::new(r#"<?xml version="1.0" encoding="UTF-8"?><root>é雪</root>"#);
    let values = [
        (1, Some(&unicode), 11),
        (2, None, 12),
        (3, Some(&declaration), 13),
    ];
    let mut request = conn.bulk_insert(&table).await?;

    for (before, xml, after) in values {
        let mut row = TokenRow::new();
        row.push(before.into_sql());
        row.push(xml.into_sql());
        row.push(after.into_sql());
        request.send(row).await?;
    }

    assert_eq!(3, request.finalize().await?.total());

    let rows = conn
        .query(
            &format!(
                "SELECT before_value, CONVERT(NVARCHAR(MAX), content), after_value FROM {} ORDER BY id",
                table
            ),
            &[],
        )
        .await
        ?
        .into_first_result()
        .await?;

    assert_eq!(Some(1), rows[0].get::<i32, _>(0));
    assert_eq!(Some(unicode.as_ref()), rows[0].get::<&str, _>(1));
    assert_eq!(Some(11), rows[0].get::<i32, _>(2));

    assert_eq!(Some(2), rows[1].get::<i32, _>(0));
    assert_eq!(None, rows[1].get::<&str, _>(1));
    assert_eq!(Some(12), rows[1].get::<i32, _>(2));

    assert_eq!(Some(3), rows[2].get::<i32, _>(0));
    assert_eq!(Some("<root>é雪</root>"), rows[2].get::<&str, _>(1));
    assert_eq!(Some(13), rows[2].get::<i32, _>(2));

    Ok(())
}

async fn assert_bulk_insert_options<S>(
    conn: &mut tiberius::Client<S>,
    options: Option<BulkLoadOptions>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let table = format!("##{}", random_table().await);
    conn.execute(
        &format!("CREATE TABLE {} (content INT NOT NULL)", table),
        &[],
    )
    .await?;

    let mut request = match options {
        Some(options) => conn.bulk_insert_with_options(&table, options).await?,
        None => conn.bulk_insert(&table).await?,
    };

    for value in [3i32, 1, 2] {
        let mut row = TokenRow::new();
        row.push(value.into_sql());
        request.send(row).await?;
    }

    assert_eq!(3, request.finalize().await?.total());

    let rows = conn
        .query(
            &format!("SELECT content FROM {} ORDER BY content", table),
            &[],
        )
        .await?
        .into_first_result()
        .await?;

    assert_eq!(Some(1), rows[0].get::<i32, _>(0));
    assert_eq!(Some(2), rows[1].get::<i32, _>(0));
    assert_eq!(Some(3), rows[2].get::<i32, _>(0));

    Ok(())
}

#[test_on_runtimes]
async fn bulk_load_default_options<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    assert_bulk_insert_options(&mut conn, None).await
}

#[test_on_runtimes]
async fn bulk_load_tablock<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    assert_bulk_insert_options(&mut conn, Some(BulkLoadOptions::new().with_tablock())).await
}

test_bulk_type!(varchar_limited(
    "VARCHAR(255)",
    1000,
    vec!["aaaaaaaaaaaaaaaaaaaaaaa"; 1000].into_iter()
));

#[cfg(all(feature = "tds73", feature = "chrono"))]
test_bulk_type!(datetime2(
    "DATETIME2",
    100,
    vec![DateTime::from_timestamp(1658524194, 123456789); 100].into_iter()
));

#[cfg(all(feature = "tds73", feature = "chrono"))]
test_bulk_type!(datetime2_naive("DATETIME2", 100, {
    #[allow(deprecated)]
    let dt = NaiveDateTime::from_timestamp_opt(1658524194, 123456789).unwrap();

    vec![dt; 100].into_iter()
}));

#[cfg(all(feature = "tds73", feature = "chrono"))]
test_bulk_type!(datetime2_0(
    "DATETIME2(0)",
    100,
    vec![DateTime::from_timestamp(1658524194, 123456789); 100].into_iter()
));

#[cfg(all(feature = "tds73", feature = "chrono"))]
test_bulk_type!(datetime2_1(
    "DATETIME2(1)",
    100,
    vec![DateTime::from_timestamp(1658524194, 123456789); 100].into_iter()
));

#[cfg(all(feature = "tds73", feature = "chrono"))]
test_bulk_type!(datetime2_2(
    "DATETIME2(2)",
    100,
    vec![DateTime::from_timestamp(1658524194, 123456789); 100].into_iter()
));

#[cfg(all(feature = "tds73", feature = "chrono"))]
test_bulk_type!(datetime2_3(
    "DATETIME2(3)",
    100,
    vec![DateTime::from_timestamp(1658524194, 123456789); 100].into_iter()
));

#[cfg(all(feature = "tds73", feature = "chrono"))]
test_bulk_type!(datetime2_4(
    "DATETIME2(4)",
    100,
    vec![DateTime::from_timestamp(1658524194, 123456789); 100].into_iter()
));

#[cfg(all(feature = "tds73", feature = "chrono"))]
test_bulk_type!(datetime2_5(
    "DATETIME2(5)",
    100,
    vec![DateTime::from_timestamp(1658524194, 123456789); 100].into_iter()
));

#[cfg(all(feature = "tds73", feature = "chrono"))]
test_bulk_type!(datetime2_6(
    "DATETIME2(6)",
    100,
    vec![DateTime::from_timestamp(1658524194, 123456789); 100].into_iter()
));

#[cfg(all(feature = "tds73", feature = "chrono"))]
test_bulk_type!(datetime2_7(
    "DATETIME2(7)",
    100,
    vec![DateTime::from_timestamp(1658524194, 123456789); 100].into_iter()
));
