//! Every tool's published schema must describe what its handler actually does.
//!
//! `tools/list` is the only thing an agent has to go on. It cannot read the
//! dispatcher, so a schema that disagrees with the handler is not a
//! documentation problem — it is a tool the agent will call wrongly, once, and
//! then be told off for.
//!
//! The seam drifts in both directions and neither is visible from one side:
//!
//! * A required argument the schema does not list makes the tool look callable
//!   with less than it needs, so the agent gets an error where the schema
//!   promised a result.
//! * An argument the schema marks required and the handler ignores makes the
//!   agent invent a value it did not have, which is worse — the call succeeds
//!   and the value was fiction.
//!
//! Driven against the surface the server actually publishes rather than against
//! a list written here, so adding a tool brings it under this test with no
//! further work.
//!
//! Verified against the reference client as well: `@modelcontextprotocol/
//! inspector --cli <sda> mcp --method tools/list` connects, negotiates and lists
//! all nineteen, and `tools/call` returns results and `isError: true` for a
//! missing argument. This file is that check made permanent and hermetic.

use serde_json::{Value, json};

/// The published surface, as `tools/list` returns it.
fn published() -> Vec<Value> {
    serde_json::to_value(sda_agent::mcp::tools()).expect("tools serialize")
        .as_array()
        .expect("an array")
        .clone()
}

fn required_of(t: &Value) -> Vec<String> {
    t["inputSchema"]["required"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).map(String::from).collect())
        .unwrap_or_default()
}

/// A value of the right *shape* for a declared property, so the only thing the
/// handler can object to is absence.
fn placeholder(schema: &Value) -> Value {
    match schema["type"].as_str() {
        Some("boolean") => json!(false),
        Some("integer") | Some("number") => json!(1),
        Some("array") => json!([]),
        Some("object") => json!({}),
        // An enum must be given one of its own members: anything else is
        // rejected for being the wrong value rather than for being absent, and
        // this test would then pass for the wrong reason.
        _ => match schema["enum"].as_array().and_then(|e| e.first()) {
            Some(first) => first.clone(),
            None => json!("placeholder"),
        },
    }
}

/// Omitting a declared-required argument must be refused, and the refusal must
/// name it.
///
/// This is the direction that matters most: the handler is the authority, and a
/// schema listing a `required` argument the handler never asks for would send an
/// agent looking for a value nobody needs.
#[test]
fn every_required_argument_is_actually_required() {
    let mut checked = 0;
    for t in published() {
        let name = t["name"].as_str().unwrap().to_string();
        let props = &t["inputSchema"]["properties"];
        let required = required_of(&t);

        for missing in &required {
            // Everything except the one under test, so absence is the only
            // possible complaint.
            let mut args = serde_json::Map::new();
            for (key, schema) in props.as_object().into_iter().flatten() {
                if key != missing {
                    args.insert(key.clone(), placeholder(schema));
                }
            }

            let r = sda_agent::dispatch::dispatch(&name, &Value::Object(args));
            let err = r.err().unwrap_or_else(|| {
                panic!(
                    "{name} declares `{missing}` required and succeeded without it; an agent \
                     reading the schema would supply a value nothing uses"
                )
            });
            assert!(
                err.contains(missing.as_str()),
                "{name} refused a call missing `{missing}` without naming it, so an agent cannot \
                 tell which argument to add: {err}"
            );
            checked += 1;
        }
    }
    assert!(checked >= 15, "the surface should have more required arguments than this: {checked}");
}

/// Nothing may be published without a schema an agent can read.
#[test]
fn every_tool_publishes_an_object_schema_with_described_properties() {
    for t in published() {
        let name = t["name"].as_str().unwrap();
        assert_eq!(t["inputSchema"]["type"], "object", "{name}");
        assert!(
            t["description"].as_str().is_some_and(|d| d.len() > 20),
            "{name} needs a description an agent can choose on"
        );
        for r in required_of(&t) {
            assert!(
                t["inputSchema"]["properties"].get(&r).is_some(),
                "{name} requires `{r}` and does not describe it, so an agent knows it must send \
                 something but not what"
            );
        }
    }
}
