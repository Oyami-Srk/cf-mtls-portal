use crate::{
    config,
    error::{AppError, Result},
};
use fs2::FileExt;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    path::Path,
    sync::Mutex,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    pub id: String,
    #[serde(skip_serializing)]
    pub owner: String,
    pub name: String,
    #[serde(skip_serializing)]
    pub cn: String,
    #[serde(skip_serializing)]
    pub cf_id: Option<String>,
    pub fingerprint: Option<String>,
    #[serde(skip_serializing)]
    pub pem: Option<String>,
    pub expires_at: Option<String>,
    pub status: String,
    pub created_at: i64,
    pub replaced_id: Option<String>,
    #[serde(skip_serializing)]
    pub spki_hash: String,
    pub error_code: Option<String>,
}
pub struct Store {
    connection: Mutex<Connection>,
    _lock: File,
}
pub fn private_dir(path: &Path) -> Result<()> {
    if let Ok(meta) = std::fs::symlink_metadata(path)
        && (meta.file_type().is_symlink() || !meta.is_dir())
    {
        return Err(AppError::internal());
    }
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
pub fn create_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
fn row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Device> {
    Ok(Device {
        id: row.get(0)?,
        owner: row.get(1)?,
        name: row.get(2)?,
        cn: row.get(3)?,
        cf_id: row.get(4)?,
        fingerprint: row.get(5)?,
        pem: row.get(6)?,
        expires_at: row.get(7)?,
        status: row.get(8)?,
        created_at: row.get(9)?,
        replaced_id: row.get(10)?,
        error_code: row.get(11)?,
        spki_hash: row.get::<_, Option<String>>(12)?.unwrap_or_default(),
    })
}
const COLUMNS: &str = "id,owner,device_name,cn,cf_id,fingerprint,pem,expires_at,status,created_at,replaced_id,error_code,spki_hash";
impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        private_dir(path)?;
        let mut options = OpenOptions::new();
        options.create(true).truncate(false).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(path.join(".server.lock"))?;
        lock.try_lock_exclusive()
            .map_err(|_| AppError::conflict("locked", "此数据目录已有运行实例。"))?;
        let database = path.join("metadata.sqlite3");
        if let Ok(meta) = std::fs::symlink_metadata(&database)
            && (meta.file_type().is_symlink() || !meta.is_file())
        {
            return Err(AppError::internal());
        }
        let existing = database.metadata().is_ok_and(|m| m.len() > 0);
        if !database.exists() {
            create_private(&database, &[])?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o600))?;
        }
        let connection = Connection::open(&database)?;
        let version: u32 = connection.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if existing && version != 1 {
            return Err(AppError::conflict(
                "database_version",
                "请先显式导入旧数据库副本，或使用兼容的数据目录。",
            ));
        }
        connection.busy_timeout(std::time::Duration::from_secs(3))?;
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA trusted_schema=OFF;
          CREATE TABLE IF NOT EXISTS certificates(id TEXT PRIMARY KEY,owner TEXT NOT NULL,device_name TEXT NOT NULL,cn TEXT NOT NULL,cf_id TEXT,fingerprint TEXT,pem TEXT,expires_at TEXT,status TEXT NOT NULL,created_at INTEGER NOT NULL,replaced_id TEXT,error_code TEXT,spki_hash TEXT);
          CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,at INTEGER NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,object_id TEXT,result TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
          CREATE INDEX IF NOT EXISTS certificates_owner_created ON certificates(owner,created_at);
          UPDATE certificates SET status='issue_uncertain' WHERE status='issuing'; PRAGMA user_version=1;")?;
        Ok(Self {
            connection: Mutex::new(connection),
            _lock: lock,
        })
    }
    pub fn with<T>(&self, f: impl FnOnce(&mut Connection) -> rusqlite::Result<T>) -> Result<T> {
        let mut guard = self.connection.lock().map_err(|_| AppError::internal())?;
        f(&mut guard).map_err(Into::into)
    }
    pub fn setting(&self, key: &str) -> Result<Option<String>> {
        self.with(|db| {
            db.query_row("SELECT value FROM settings WHERE key=?", [key], |r| {
                r.get(0)
            })
            .optional()
        })
    }
    pub fn set(&self, key: &str, value: &str) -> Result<()> {
        self.with(|db|db.execute("INSERT INTO settings VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",params![key,value]).map(|_|()))
    }
    pub fn audit(&self, owner: &str, action: &str, id: &str, result: &str) -> Result<()> {
        self.with(|db| {
            db.execute(
                "INSERT INTO audit(at,actor,action,object_id,result) VALUES(?,?,?,?,?)",
                params![
                    chrono::Utc::now().timestamp_millis(),
                    owner,
                    action,
                    id,
                    result
                ],
            )
            .map(|_| ())
        })
    }
    pub fn devices(&self, owner: &str) -> Result<Vec<Device>> {
        self.with(|db| {
            db.prepare(&format!(
                "SELECT {COLUMNS} FROM certificates WHERE owner=? ORDER BY created_at DESC"
            ))?
            .query_map([owner], row)?
            .collect()
        })
    }
    pub fn device(&self, id: &str, owner: &str) -> Result<Device> {
        self.with(|db| {
            db.query_row(
                &format!("SELECT {COLUMNS} FROM certificates WHERE id=? AND owner=?"),
                params![id, owner],
                row,
            )
            .optional()
        })?
        .ok_or_else(|| AppError::bad("not_found", "设备不存在。"))
    }
    pub fn active_fingerprints(&self) -> Result<Vec<String>> {
        self.with(|db|db.prepare("SELECT fingerprint FROM certificates WHERE status='active' AND fingerprint IS NOT NULL")?.query_map([],|r|r.get(0))?.collect())
    }
    pub fn insert(&self, device: &Device, limit: u16, daily: u16) -> Result<()> {
        let mut db = self.connection.lock().map_err(|_| AppError::internal())?;
        let tx = db.transaction()?;
        let count:i64=tx.query_row("SELECT count(*) FROM certificates WHERE owner=? AND status NOT IN ('revoked','failed')",[&device.owner],|r|r.get(0))?;
        let day: i64 = tx.query_row(
            "SELECT count(*) FROM certificates WHERE owner=? AND created_at>?",
            params![
                device.owner,
                chrono::Utc::now().timestamp_millis() - 86_400_000
            ],
            |r| r.get(0),
        )?;
        if count >= i64::from(limit) || day >= i64::from(daily) {
            return Err(AppError::busy());
        }
        tx.execute("INSERT INTO certificates(id,owner,device_name,cn,status,created_at,replaced_id,spki_hash) VALUES(?,?,?,?,?,?,?,?)",params![device.id,device.owner,device.name,device.cn,device.status,device.created_at,device.replaced_id,device.spki_hash])?;
        tx.commit()?;
        Ok(())
    }
    pub fn issued(
        &self,
        id: &str,
        cf_id: &str,
        pem: &str,
        fingerprint: &str,
        expires: &str,
    ) -> Result<()> {
        self.with(|db|db.execute("UPDATE certificates SET cf_id=?,pem=?,fingerprint=?,expires_at=?,status='issued_pending_allow',error_code=NULL WHERE id=?",params![cf_id,pem,fingerprint,expires,id]).map(|_|()))
    }
    pub fn status(&self, id: &str, status: &str, error: Option<&str>) -> Result<()> {
        self.with(|db| {
            db.execute(
                "UPDATE certificates SET status=?,error_code=? WHERE id=?",
                params![status, error, id],
            )
            .map(|_| ())
        })
    }
    pub fn import(source: &Path, destination: &Path) -> Result<()> {
        if destination.exists() {
            return Err(AppError::conflict("exists", "目标数据库已存在，拒绝覆盖。"));
        }
        let parent = destination.parent().ok_or_else(AppError::internal)?;
        private_dir(parent)?;
        // Import accepts an offline copy, never a live database or an untrusted SQL script.
        let src = Connection::open_with_flags(source, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let check: String = src.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
        if check != "ok" {
            return Err(AppError::bad("database", "源数据库完整性检查失败。"));
        }
        let records: Vec<Device> = src
            .prepare(&format!("SELECT {COLUMNS} FROM certificates"))?
            .query_map([], row)?
            .collect::<rusqlite::Result<_>>()?;
        if records.iter().any(|d| {
            uuid::Uuid::parse_str(&d.id).is_err()
                || d.fingerprint.as_ref().is_some_and(|x| !config::hex(x, 64))
                || ![
                    "issuing",
                    "issue_uncertain",
                    "issued_pending_allow",
                    "active",
                    "blocked_pending_revoke",
                    "revoked",
                    "failed",
                ]
                .contains(&d.status.as_str())
        }) {
            return Err(AppError::bad("database", "源数据不符合设备格式要求。"));
        }
        create_private(destination, &[])?;
        let mut target = Connection::open(destination)?;
        {
            let backup = rusqlite::backup::Backup::new(&src, &mut target)?;
            backup.run_to_completion(100, std::time::Duration::from_millis(10), None)?;
        }
        target.execute_batch("PRAGMA user_version=1;")?;
        Ok(())
    }
}
