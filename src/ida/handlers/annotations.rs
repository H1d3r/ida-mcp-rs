//! Comment and rename handlers.

use std::path::Path;

use crate::error::ToolError;
use crate::ida::handlers::target::{resolve_mutation_target, TargetSpec};
use idalib::IDB;
use serde_json::{json, Value};

pub(crate) fn handle_set_comments(
    idb: &Option<IDB>,
    database: Option<&Path>,
    target: TargetSpec<'_>,
    comment: &str,
    repeatable: bool,
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let (addr, target) = resolve_mutation_target(db, database, target)?;
    if repeatable {
        db.set_cmt_with(addr, comment, true)?;
    } else {
        db.set_cmt(addr, comment)?;
    }
    Ok(json!({
        "address": format!("{:#x}", addr),
        "repeatable": repeatable,
        "comment": comment,
        "target": target,
    }))
}

/// Rename the target. `target.symbol` in the result is the name before the
/// rename; `name` is the name it has now.
pub(crate) fn handle_rename(
    idb: &Option<IDB>,
    database: Option<&Path>,
    target: TargetSpec<'_>,
    name: &str,
    flags: i32,
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let (addr, target) = resolve_mutation_target(db, database, target)?;
    if flags == 0 {
        db.set_name(addr, name)?;
    } else {
        db.set_name_with_flags(addr, name, flags)?;
    }
    Ok(json!({
        "address": format!("{:#x}", addr),
        "name": name,
        "flags": flags,
        "target": target,
    }))
}
