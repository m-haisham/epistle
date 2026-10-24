use epistle_core::{Pointer, hash, id, now};
use epistle_delivery::Prepared;
use epistle_store::{Error, Store};
use sqlx::{Row, SqliteConnection};

// Caller owns the transaction, so discovery and cursor movement are one durable change.
pub async fn enqueue(
    c: &mut SqliteConnection,
    p: &Pointer,
    origin: &str,
    job: Option<&str>,
    redeliver: bool,
) -> Result<bool, Error> {
    let identity = hash(p.identity().as_bytes());
    let existing: Option<String> =
        sqlx::query_scalar("SELECT message_key FROM seen WHERE account_id=? AND message_id_hash=?")
            .bind(&p.account_id)
            .bind(&identity)
            .fetch_optional(&mut *c)
            .await?;
    let key = existing.clone().unwrap_or_else(id);
    let pointer = serde_json::to_string(p)?;
    sqlx::query("INSERT INTO message_index(message_key,account_id,folder_id,uidvalidity,uid,rfc_message_id,pointer,created_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(message_key) DO UPDATE SET folder_id=excluded.folder_id,uidvalidity=excluded.uidvalidity,uid=excluded.uid,rfc_message_id=excluded.rfc_message_id,pointer=excluded.pointer,created_at=excluded.created_at")
 .bind(&key).bind(&p.account_id).bind(&p.folder_id).bind(p.uidvalidity).bind(p.uid).bind(&p.rfc_message_id).bind(&pointer).bind(now()).execute(&mut *c).await?;
    if existing.is_some() && !redeliver {
        return Ok(false);
    }
    let idem = if redeliver {
        format!("{}:{}", p.key(), job.unwrap_or("live"))
    } else {
        p.key()
    };
    let inserted=sqlx::query("INSERT OR IGNORE INTO fetch_queue(id,idempotency_key,account_id,message_key,pointer,origin,backfill_id,created_at) VALUES(?,?,?,?,?,?,?,?)")
 .bind(id()).bind(idem).bind(&p.account_id).bind(&key).bind(pointer).bind(origin).bind(job).bind(now()).execute(&mut *c).await?.rows_affected()>0;
    sqlx::query("INSERT OR IGNORE INTO seen(account_id,message_id_hash,message_key,first_seen_at) VALUES(?,?,?,?)").bind(&p.account_id).bind(identity).bind(key).bind(now()).execute(c).await?;
    Ok(inserted)
}
pub async fn handoff(store: &Store, stub: String, prepared: Prepared) -> Result<(), Error> {
    store.write(move|c|Box::pin(async move{
  let row=sqlx::query("SELECT idempotency_key,backfill_id FROM fetch_queue WHERE id=?").bind(&stub).fetch_optional(&mut *c).await?;
  let Some(row)=row else{return Ok(())};
  let key=&prepared.message.id;let account=&prepared.message.account_id;
  sqlx::query("INSERT INTO messages(id,account_id,payload_path,created_at) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET payload_path=excluded.payload_path,expired=0,expires_at=NULL").bind(key).bind(account).bind(&prepared.payload_path).bind(now()).execute(&mut *c).await?;
  for f in prepared.files {let m=f.manifest;sqlx::query("INSERT INTO message_files(message_key,file_id,role,filename,content_type,size,sha256,content_id,path) VALUES(?,?,?,?,?,?,?,?,?)")
   .bind(key).bind(m.id).bind(m.role).bind(m.filename).bind(m.content_type).bind(m.size).bind(m.sha256).bind(m.content_id).bind(f.path).execute(&mut *c).await?;}
  sqlx::query("UPDATE message_files SET expires_at=NULL WHERE message_key=? AND expired=0").bind(key).execute(&mut *c).await?;
  sqlx::query("INSERT OR IGNORE INTO outbox(idempotency_key,message_key,account_id,kind,payload_path,backfill_id,size_bytes,created_at) VALUES(?,?,?,'email.message.received',?,?,?,?)")
   .bind(row.try_get::<String,_>("idempotency_key")?).bind(key).bind(account).bind(prepared.payload_path).bind(row.try_get::<Option<String>,_>("backfill_id")?).bind(prepared.payload_size).bind(now()).execute(&mut *c).await?;
  sqlx::query("DELETE FROM fetch_queue WHERE id=?").bind(stub).execute(c).await?;Ok(())
 })).await
}
