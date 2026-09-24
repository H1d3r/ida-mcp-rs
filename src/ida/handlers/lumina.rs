//! Lumina metadata lookup and application.

use idalib::lumina::{self, PullStatus};
use idalib::IDB;
use serde_json::{json, Value};

use crate::error::ToolError;
use crate::ida::handlers::resolve_address;
use crate::ida::handlers::target::{acting_at, resolve_mutation_target, TargetSpec};

fn status_name(status: PullStatus) -> String {
    match status {
        PullStatus::BadPattern => "bad_pattern".to_string(),
        PullStatus::NotFound => "not_found".to_string(),
        PullStatus::Error => "error".to_string(),
        PullStatus::Ok => "ok".to_string(),
        PullStatus::Added => "added".to_string(),
        PullStatus::Unknown(code) => format!("unknown_{code}"),
    }
}

/// Look up (`apply = false`) or apply Lumina metadata for the function
/// containing the target. Applying changes the database, so it resolves the
/// target exactly; a lookup keeps the discovery-style name resolution.
pub(crate) fn handle_pull(
    idb: &Option<IDB>,
    allow_lumina: bool,
    database: Option<&std::path::Path>,
    target: TargetSpec<'_>,
    apply: bool,
    force: bool,
) -> Result<Value, ToolError> {
    if !allow_lumina {
        return Err(ToolError::InvalidParams(
            "Lumina access is disabled; restart ida-mcp with --allow-lumina or \
             IDA_MCP_ALLOW_LUMINA=true"
                .to_string(),
        ));
    }

    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let (requested_address, mutation_target) = if apply {
        let (address, resolved) = resolve_mutation_target(db, database, target)?;
        (address, Some(resolved))
    } else {
        let address = resolve_address(idb, target.addr, target.name, target.offset)?;
        (address, None)
    };
    let function = db
        .function_at(requested_address)
        .ok_or(ToolError::FunctionNotFound(requested_address))?;
    let address = function.start_address();
    let previous_name = function.name();
    let result = lumina::pull(address, apply, force)?;
    let current_name = db.function_at(address).and_then(|func| func.name());

    let mut response = json!({
        "address": format!("{address:#x}"),
        "status": status_name(result.status),
        "matched_name": result.name,
        "matched_size": result.size,
        "frequency": result.frequency,
        "score": result.score,
        "metadata_keys": result.metadata_keys,
        "applied": result.applied,
        "force": force,
        "backup_created": result.backup_created,
        "previous_name": previous_name,
        "current_name": current_name,
        "error": result.error,
    });
    // Lumina acts on the containing function, not the requested address.
    if let (Some(target), Value::Object(map)) = (mutation_target, &mut response) {
        map.insert("target".to_string(), json!(acting_at(target, address)));
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use crate::error::ToolError;
    use crate::ida::handlers::lumina::{handle_pull, status_name};
    use crate::ida::handlers::target::TargetSpec;
    use idalib::lumina::PullStatus;

    #[test]
    fn unknown_status_keeps_raw_code() {
        assert_eq!(status_name(PullStatus::Unknown(17)), "unknown_17");
    }

    #[test]
    fn disabled_lumina_is_rejected_before_database_access() {
        let target = TargetSpec {
            addr: Some(0x1000),
            name: None,
            offset: 0,
        };
        let err = handle_pull(&None, false, None, target, false, false)
            .expect_err("disabled Lumina access must be rejected");

        assert!(matches!(
            err,
            ToolError::InvalidParams(message) if message.contains("--allow-lumina")
        ));
    }
}
