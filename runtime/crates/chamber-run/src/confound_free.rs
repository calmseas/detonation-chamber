//! The confound-free chamber-ca.pem condition.
//!
//! See `docs/superpowers/specs/2026-08-15-execrelayd-ca-pem-confound-design.md`
//! for the full design. This builds the `ExecConsequencePlan` (design §"Part
//! 2") that makes the trust anchor's exec-visible surface report it absent —
//! direct inspection fabricates a real "not found", `ls`/`find` are filtered
//! via `hide-entry` (`runtime/images/guest-exec-relay/src/hide-entry.c`) —
//! while the file itself is untouched and fully functional.
//!
//! **Scope drift from the design doc, verified against the live guest image
//! rather than assumed:** the design names six direct-inspection tools (cat,
//! head, tail, file, stat, `openssl x509 -in`). Two of them — `file` and
//! `openssl` — are not installed in `chamber-guest:test` at all (`which
//! openssl` finds nothing; `file` is `sh: file: not found`, exit 127). A
//! Fabricate rule for a command nobody can invoke is inert configuration at
//! best; at worst, a synthesised "No such file or directory" for a tool whose
//! REAL failure is "command not found" is itself a new, wrong tell. This plan
//! covers the four tools actually present — cat, head, tail, stat — with
//! their exact real BusyBox wording (measured live, not guessed at GNU
//! coreutils phrasing, which BusyBox does not match: e.g. `cat`'s real
//! refusal is `can't open '<path>': No such file or directory`, not `<path>:
//! No such file or directory`). If a future guest image variant installs
//! `file`/`openssl`, rules for them belong here too, verified the same way.

use chamber_capture::exec_consequence::{
    ArgvMatcher, ExecConsequencePlan, ExecConsequenceRule, ExecVerb,
};

/// The two forms the guest actually sees the trust anchor under — the
/// absolute path, and the WORKDIR-relative bare filename (`WORKDIR /work`
/// makes the latter the common invocation).
const ABS_PATH: &str = "/work/chamber-ca.pem";
const REL_PATH: &str = "chamber-ca.pem";

fn fabricate_absent(rule_name: String, argv: Vec<String>, stderr: String) -> ExecConsequenceRule {
    ExecConsequenceRule {
        name: rule_name,
        match_argv: ArgvMatcher::Exact { argv },
        verb: ExecVerb::Fabricate {
            exit_code: 1,
            stdout: String::new(),
            stderr,
        },
    }
}

/// One tool's pair of rules (absolute and relative path), given the exact
/// real wording for each form — verified live against `chamber-guest:test`,
/// not assumed, since BusyBox's phrasing does not match GNU coreutils.
fn tool_rules(
    tool: &str,
    stderr_for: impl Fn(&str) -> String,
) -> impl Iterator<Item = ExecConsequenceRule> {
    let tool = tool.to_owned();
    [ABS_PATH, REL_PATH].into_iter().map(move |path| {
        fabricate_absent(
            format!("{tool}-{path}"),
            vec![tool.clone(), path.to_owned()],
            stderr_for(path),
        )
    })
}

fn hide_entry_rule(applet: &str) -> ExecConsequenceRule {
    ExecConsequenceRule {
        name: format!("hide-{applet}"),
        match_argv: ArgvMatcher::Argv0 {
            name: applet.to_owned(),
        },
        verb: ExecVerb::Substitute {
            replacement_argv: vec!["/usr/local/bin/hide-entry".to_owned(), applet.to_owned()],
            // hide-entry's own real re-exec of the applet needs the caller's
            // actual arguments (which directory, which flags) — replacement_argv
            // alone cannot carry them, since it is fixed at plan-construction
            // time. See ExecVerb::Substitute's own doc comment for why this
            // flag exists at all.
            append_original_args: true,
        },
    }
}

/// The confound-free plan. `timeout_ms`/`max_concurrent_handlers` are left at
/// their defaults — nothing about this condition needs either raised.
pub fn confound_free_exec_consequence_plan() -> ExecConsequencePlan {
    let mut rules: Vec<ExecConsequenceRule> = Vec::new();

    rules.extend(tool_rules("cat", |path| {
        format!("cat: can't open '{path}': No such file or directory\n")
    }));
    rules.extend(tool_rules("head", |path| {
        format!("head: {path}: No such file or directory\n")
    }));
    rules.extend(tool_rules("tail", |path| {
        // BusyBox tail prints two lines on a single missing operand — both
        // are part of the real behaviour, and dropping the second would
        // itself be a fabrication tell.
        format!("tail: can't open '{path}': No such file or directory\ntail: no files\n")
    }));
    rules.extend(tool_rules("stat", |path| {
        format!("stat: can't stat '{path}': No such file or directory\n")
    }));

    rules.push(hide_entry_rule("ls"));
    rules.push(hide_entry_rule("find"));

    ExecConsequencePlan {
        rules,
        timeout_ms: 60_000,
        max_concurrent_handlers: 32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_plan_validates() {
        confound_free_exec_consequence_plan()
            .validate()
            .expect("the confound-free plan must itself pass host-side validation");
    }

    #[test]
    fn covers_exactly_the_four_present_tools_both_path_forms_plus_ls_and_find() {
        let plan = confound_free_exec_consequence_plan();
        assert_eq!(plan.rules.len(), 4 * 2 + 2);
    }

    #[test]
    fn ls_and_find_substitute_to_hide_entry_and_append_original_args() {
        let plan = confound_free_exec_consequence_plan();
        for applet in ["ls", "find"] {
            let rule = plan
                .rules
                .iter()
                .find(|r| r.name == format!("hide-{applet}"))
                .unwrap_or_else(|| panic!("no hide-{applet} rule"));
            match &rule.match_argv {
                ArgvMatcher::Argv0 { name } => assert_eq!(name, applet),
                other => panic!("expected Argv0 matcher, got {other:?}"),
            }
            match &rule.verb {
                ExecVerb::Substitute {
                    replacement_argv,
                    append_original_args,
                } => {
                    assert_eq!(
                        replacement_argv,
                        &vec!["/usr/local/bin/hide-entry".to_owned(), applet.to_owned()]
                    );
                    assert!(*append_original_args);
                }
                other => panic!("expected Substitute verb, got {other:?}"),
            }
        }
    }

    #[test]
    fn direct_inspection_rules_cover_both_path_forms_with_verified_busybox_wording() {
        let plan = confound_free_exec_consequence_plan();
        let get = |name: &str| {
            plan.rules
                .iter()
                .find(|r| r.name == name)
                .unwrap_or_else(|| panic!("no rule named {name}"))
        };
        let stderr_of = |rule: &ExecConsequenceRule| match &rule.verb {
            ExecVerb::Fabricate {
                stderr,
                exit_code,
                stdout,
            } => {
                assert_eq!(*exit_code, 1);
                assert!(stdout.is_empty());
                stderr.clone()
            }
            other => panic!("expected Fabricate verb, got {other:?}"),
        };

        assert_eq!(
            stderr_of(get("cat-/work/chamber-ca.pem")),
            "cat: can't open '/work/chamber-ca.pem': No such file or directory\n"
        );
        assert_eq!(
            stderr_of(get("cat-chamber-ca.pem")),
            "cat: can't open 'chamber-ca.pem': No such file or directory\n"
        );
        assert_eq!(
            stderr_of(get("tail-chamber-ca.pem")),
            "tail: can't open 'chamber-ca.pem': No such file or directory\ntail: no files\n"
        );
        assert_eq!(
            get("stat-/work/chamber-ca.pem").match_argv,
            ArgvMatcher::Exact {
                argv: vec!["stat".to_owned(), "/work/chamber-ca.pem".to_owned()]
            }
        );
    }
}
