//! The agentic layer.
//!
//! Three pieces, in increasing order of autonomy:
//!
//! * [`plan`] — a deterministic planner that decides what to run and states what
//!   will not be covered.
//! * [`mcp`] — an MCP tool surface publishing the whole toolkit to any agent
//!   that speaks the protocol, with each tool's limits in its description.
//! * [`swe`] — the autonomous build-diagnose-patch-verify loop, which owns the
//!   evidence and the stopping decision so the model does not have to be trusted
//!   with either.

#![forbid(unsafe_code)]

pub mod dispatch;
pub mod mcp;
pub mod plan;
pub mod swe;

pub use dispatch::dispatch;
pub use mcp::{ToolDef, serve_stdio, tools};
pub use plan::{Plan, PlanInputs, plan};
pub use swe::{Iteration, Session, Stop, WorkItem};

/// Serve the MCP surface over stdio with the real dispatcher.
pub fn serve() -> std::io::Result<()> {
    mcp::serve_stdio(&|name, args| dispatch::dispatch(name, args))
}
