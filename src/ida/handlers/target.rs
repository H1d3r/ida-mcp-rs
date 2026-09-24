//! Exact target resolution for mutating tools.
//!
//! Discovery tools resolve names loosely (see `resolve_address`); tools that
//! change the database must not. A mutation targets exactly one address or
//! one name that matches a symbol literally and case-sensitively. Anything
//! else fails with a bounded, deterministic list of similar names and their
//! addresses, and never picks one of them.

use std::collections::BTreeSet;
use std::path::Path;

use idalib::IDB;

use crate::error::ToolError;
use crate::ida::types::{MutationTarget, TargetSelector};

/// Most suggestions listed when a name has no exact match.
const MAX_SUGGESTIONS: usize = 8;
/// Most addresses listed when one exact name has several.
const MAX_AMBIGUOUS_LISTED: usize = 8;

/// A mutating tool's target as the caller specified it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct TargetSpec<'a> {
    pub addr: Option<u64>,
    pub name: Option<&'a str>,
    /// Added to the resolved base to get the address the tool acts on.
    pub offset: i64,
}

/// Outcome of matching a name literally against the database's names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NameMatch {
    Unique {
        address: u64,
        name: String,
    },
    /// The same exact name at more than one address: the lowest addresses,
    /// and whether there are more than those listed.
    Ambiguous {
        listed: Vec<(u64, String)>,
        more: bool,
    },
    /// No exact match; similar names, best first.
    Missing(Vec<(u64, String)>),
}

/// How close a non-matching `name` is to `query`, lower is closer.
fn suggestion_rank(query: &str, name: &str) -> Option<u8> {
    if name.trim_start_matches('_') == query.trim_start_matches('_') {
        Some(0)
    } else if name.eq_ignore_ascii_case(query) {
        Some(1)
    } else if name.contains(query) {
        Some(2)
    } else if name
        .to_ascii_lowercase()
        .contains(&query.to_ascii_lowercase())
    {
        Some(3)
    } else {
        None
    }
}

/// Add `item` to an ordered set holding at most `limit` of the smallest
/// items. Returns whether an item had to be dropped.
fn keep_smallest<T: Ord>(set: &mut BTreeSet<T>, item: T, limit: usize) -> bool {
    set.insert(item);
    set.len() > limit && set.pop_last().is_some()
}

/// Match `query` literally and case-sensitively against `(address, name)`
/// candidates. Candidates may repeat (a function name is usually also in the
/// name list); exact matches are counted per address.
///
/// Every candidate is scanned, since uniqueness needs the whole list, but
/// only the best few exact matches and suggestions are kept: two distinct
/// exact addresses always leave at least two in the bounded set, so the
/// unique/ambiguous decision stays exact.
pub(crate) fn match_name(
    query: &str,
    candidates: impl IntoIterator<Item = (u64, String)>,
) -> NameMatch {
    let mut exact: BTreeSet<(u64, String)> = BTreeSet::new();
    let mut more_exact = false;
    let mut similar: BTreeSet<(u8, u64, String)> = BTreeSet::new();
    for (address, name) in candidates {
        if name == query {
            more_exact |= keep_smallest(&mut exact, (address, name), MAX_AMBIGUOUS_LISTED);
        } else if let Some(rank) = suggestion_rank(query, &name) {
            keep_smallest(&mut similar, (rank, address, name), MAX_SUGGESTIONS);
        }
    }
    if exact.len() > 1 {
        return NameMatch::Ambiguous {
            listed: exact.into_iter().collect(),
            more: more_exact,
        };
    }
    match exact.pop_first() {
        Some((address, name)) => NameMatch::Unique { address, name },
        None => NameMatch::Missing(
            similar
                .into_iter()
                .map(|(_, address, name)| (address, name))
                .collect(),
        ),
    }
}

fn describe(names: &[(u64, String)]) -> String {
    names
        .iter()
        .map(|(address, name)| format!("\"{name}\" at {address:#x}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn missing_name_error(query: &str, suggestions: &[(u64, String)]) -> ToolError {
    let hint = if suggestions.is_empty() {
        "use lookup_funcs or list_functions to find the exact name".to_string()
    } else {
        format!("similar names: {}", describe(suggestions))
    };
    ToolError::InvalidParams(format!(
        "no symbol is named exactly \"{query}\"; {hint}. Mutating tools act only on an exact, \
         case-sensitive name or an address"
    ))
}

/// The name listed exactly at `address`, if any. Generated names such as
/// `sub_…` are not in IDA's name list, so an unnamed address yields `None`.
fn listed_name_at(db: &IDB, address: u64) -> Option<String> {
    let names = db.names();
    if !names.has_name(address) {
        return None;
    }
    names
        .get_closest_by_address(address)
        .filter(|name| name.address() == address)
        .map(|name| name.name().to_string())
}

fn resolve_exact_name(db: &IDB, query: &str) -> Result<(u64, String), ToolError> {
    let functions = db
        .functions()
        .filter_map(|(_, func)| func.name().map(|name| (func.start_address(), name)));
    let name_list = db.names();
    let listed = name_list
        .iter()
        .map(|name| (name.address(), name.name().to_string()));
    match match_name(query, functions.chain(listed)) {
        NameMatch::Unique { address, name } => Ok((address, name)),
        NameMatch::Missing(suggestions) => Err(missing_name_error(query, &suggestions)),
        NameMatch::Ambiguous { listed, more } => Err(ToolError::InvalidParams(format!(
            "\"{query}\" names more than one address ({}{}); pass the address instead",
            describe(&listed),
            if more { ", and others" } else { "" }
        ))),
    }
}

/// Resolve a mutating tool's target before it changes anything.
///
/// Exactly one of `spec.addr` and `spec.name` must be set. Returns the
/// address to act on (the resolved base plus `spec.offset`) and the record
/// to report with the result.
pub(crate) fn resolve_mutation_target(
    db: &IDB,
    database: Option<&Path>,
    spec: TargetSpec<'_>,
) -> Result<(u64, MutationTarget), ToolError> {
    let (selector, base, symbol) = match (spec.addr, spec.name) {
        (Some(_), Some(_)) => {
            return Err(ToolError::InvalidParams(
                "pass either an address or a name for the target, not both".to_string(),
            ));
        }
        (None, None) => {
            return Err(ToolError::InvalidParams(
                "pass an address or an exact name for the target".to_string(),
            ));
        }
        (Some(address), None) => (
            TargetSelector::Address,
            address,
            listed_name_at(db, address),
        ),
        (None, Some(query)) => {
            let (address, name) = resolve_exact_name(db, query)?;
            (TargetSelector::Name, address, Some(name))
        }
    };
    let address = base.checked_add_signed(spec.offset).ok_or_else(|| {
        ToolError::InvalidParams(format!(
            "offset {} produces an out-of-range address from base {base:#x}",
            spec.offset
        ))
    })?;
    Ok((
        address,
        MutationTarget {
            database: database.map(|path| path.display().to_string()),
            selector,
            symbol,
            base: format!("{base:#x}"),
            requested_address: format!("{address:#x}"),
            address: format!("{address:#x}"),
        },
    ))
}

/// Record that a tool acts on `address` instead of the requested address,
/// keeping `requested_address` as the caller asked.
pub(crate) fn acting_at(target: MutationTarget, address: u64) -> MutationTarget {
    MutationTarget {
        address: format!("{address:#x}"),
        ..target
    }
}

#[cfg(test)]
mod tests {
    use crate::ida::handlers::target::{
        acting_at, match_name, missing_name_error, NameMatch, MAX_AMBIGUOUS_LISTED, MAX_SUGGESTIONS,
    };
    use crate::ida::types::{MutationTarget, TargetSelector};

    #[test]
    fn normalizing_keeps_the_requested_address() {
        // lumina_apply given an interior address acts on the function start.
        let requested = MutationTarget {
            database: None,
            selector: TargetSelector::Address,
            symbol: None,
            base: "0x1004".to_string(),
            requested_address: "0x1004".to_string(),
            address: "0x1004".to_string(),
        };
        let normalized = acting_at(requested.clone(), 0x1000);
        assert_eq!(normalized.address, "0x1000");
        assert_eq!(normalized.requested_address, "0x1004");
        assert_eq!(normalized.base, "0x1004");
        assert_eq!(
            MutationTarget {
                address: requested.address.clone(),
                ..normalized
            },
            requested,
            "only the acted-on address changes"
        );
    }

    fn names(entries: &[(u64, &str)]) -> Vec<(u64, String)> {
        entries
            .iter()
            .map(|(address, name)| (*address, (*name).to_string()))
            .collect()
    }

    #[test]
    fn exact_match_wins_over_an_earlier_substring_candidate() {
        let candidates = names(&[(0x100, "domain_check"), (0x200, "main")]);
        assert_eq!(
            match_name("main", candidates),
            NameMatch::Unique {
                address: 0x200,
                name: "main".to_string()
            }
        );
    }

    #[test]
    fn main_and_underscore_main_each_match_only_themselves() {
        let candidates = names(&[(0x100, "_main"), (0x200, "main")]);
        assert_eq!(
            match_name("main", candidates.clone()),
            NameMatch::Unique {
                address: 0x200,
                name: "main".to_string()
            }
        );
        assert_eq!(
            match_name("_main", candidates),
            NameMatch::Unique {
                address: 0x100,
                name: "_main".to_string()
            }
        );
    }

    #[test]
    fn missing_name_suggests_without_selecting() {
        let candidates = names(&[
            (0x300, "MAIN"),
            (0x080, "domain_check"),
            (0x100, "_main"),
            (0x400, "unrelated"),
        ]);
        assert_eq!(
            match_name("main", candidates),
            NameMatch::Missing(names(&[
                (0x100, "_main"),
                (0x300, "MAIN"),
                (0x080, "domain_check"),
            ]))
        );
    }

    #[test]
    fn matching_is_case_sensitive() {
        let candidates = names(&[(0x100, "main")]);
        assert_eq!(
            match_name("Main", candidates),
            NameMatch::Missing(names(&[(0x100, "main")]))
        );
    }

    #[test]
    fn duplicate_candidates_at_one_address_are_one_match() {
        // A function's name usually appears in the function list and the
        // name list.
        let candidates = names(&[(0x100, "_main"), (0x100, "_main"), (0x200, "_main_x")]);
        assert_eq!(
            match_name("_main", candidates),
            NameMatch::Unique {
                address: 0x100,
                name: "_main".to_string()
            }
        );
    }

    #[test]
    fn one_name_at_two_addresses_is_ambiguous() {
        let candidates = names(&[(0x200, "dup"), (0x100, "dup")]);
        assert_eq!(
            match_name("dup", candidates),
            NameMatch::Ambiguous {
                listed: names(&[(0x100, "dup"), (0x200, "dup")]),
                more: false,
            }
        );
    }

    #[test]
    fn ambiguity_lists_the_lowest_addresses_and_says_there_are_more() {
        // Each address appears twice, as it would from the function list
        // and the name list; repeats are not "more".
        let entries: Vec<(u64, String)> = (0..20_u64)
            .rev()
            .flat_map(|index| {
                let entry = (0x100 + index, "dup".to_string());
                [entry.clone(), entry]
            })
            .collect();
        let NameMatch::Ambiguous { listed, more } = match_name("dup", entries) else {
            panic!("expected an ambiguous match");
        };
        let expected: Vec<(u64, String)> = (0..MAX_AMBIGUOUS_LISTED as u64)
            .map(|index| (0x100 + index, "dup".to_string()))
            .collect();
        assert_eq!(listed, expected);
        assert!(more);

        let exactly_full: Vec<(u64, String)> = (0..MAX_AMBIGUOUS_LISTED as u64)
            .flat_map(|index| {
                let entry = (0x100 + index, "dup".to_string());
                [entry.clone(), entry]
            })
            .collect();
        let NameMatch::Ambiguous { more, .. } = match_name("dup", exactly_full) else {
            panic!("expected an ambiguous match");
        };
        assert!(!more, "repeats of listed addresses must not count as more");
    }

    #[test]
    fn exact_match_survives_many_similar_names() {
        // A broad query like "_" is similar to every underscore symbol; the
        // one exact match must still win.
        let mut entries: Vec<(u64, String)> = (0..10_000_u64)
            .map(|index| (0x1000 + index, format!("_sym_{index}")))
            .collect();
        entries.push((0x10, "_".to_string()));
        assert_eq!(
            match_name("_", entries),
            NameMatch::Unique {
                address: 0x10,
                name: "_".to_string()
            }
        );
    }

    #[test]
    fn suggestions_are_bounded_and_deterministic() {
        let mut entries: Vec<(u64, String)> = (0..40)
            .map(|index| (0x1000 - index * 0x10, format!("helper_main_{index}")))
            .collect();
        let first = match_name("main", entries.clone());
        entries.reverse();
        let second = match_name("main", entries);
        assert_eq!(first, second, "order of input must not matter");
        let NameMatch::Missing(suggestions) = first else {
            panic!("expected suggestions");
        };
        assert_eq!(suggestions.len(), MAX_SUGGESTIONS);
        assert!(
            suggestions.windows(2).all(|pair| pair[0].0 < pair[1].0),
            "same-rank suggestions are ordered by address: {suggestions:?}"
        );
    }

    #[test]
    fn missing_name_error_lists_addresses_or_points_to_discovery() {
        let with = missing_name_error("main", &names(&[(0x100, "_main")])).to_string();
        assert!(
            with.contains("no symbol is named exactly \"main\""),
            "{with}"
        );
        assert!(with.contains("\"_main\" at 0x100"), "{with}");
        let without = missing_name_error("zzz", &[]).to_string();
        assert!(without.contains("lookup_funcs"), "{without}");
    }
}
