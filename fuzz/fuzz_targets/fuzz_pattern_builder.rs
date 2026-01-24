//! Fuzz target for PatternBuilder
//!
//! Tests that arbitrary string inputs to PatternBuilder don't cause panics
//! or undefined behavior.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use geode_client::{EdgeDirection, PatternBuilder};

#[derive(Debug, Arbitrary)]
enum FuzzDirection {
    Outgoing,
    Incoming,
    Undirected,
}

impl From<FuzzDirection> for EdgeDirection {
    fn from(d: FuzzDirection) -> Self {
        match d {
            FuzzDirection::Outgoing => EdgeDirection::Outgoing,
            FuzzDirection::Incoming => EdgeDirection::Incoming,
            FuzzDirection::Undirected => EdgeDirection::Undirected,
        }
    }
}

#[derive(Debug, Arbitrary)]
enum PatternElement {
    Node { variable: String, label: String },
    Edge { variable: String, edge_type: String, direction: FuzzDirection },
}

#[derive(Debug, Arbitrary)]
struct PatternInput {
    elements: Vec<PatternElement>,
}

fuzz_target!(|input: PatternInput| {
    let mut builder = PatternBuilder::new();

    for element in input.elements {
        match element {
            PatternElement::Node { variable, label } => {
                builder = builder.node(&variable, &label);
            }
            PatternElement::Edge { variable, edge_type, direction } => {
                builder = builder.edge(&variable, &edge_type, direction.into());
            }
        }
    }

    // Build should never panic
    let pattern = builder.build();

    // Result should be usable
    let _ = pattern.len();
    let _ = pattern.is_empty();
    let _ = pattern.contains("(");
});
