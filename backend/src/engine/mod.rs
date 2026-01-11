pub mod actions;
mod executor;
pub(crate) mod graph;
pub(crate) mod nodes;
mod templating;

pub(crate) use actions::registry::ActionRegistry;

pub(crate) use executor::{complete_run_with_retry, execute_run};
pub use executor::ExecutorError;

pub(crate) fn build_action_registry() -> ActionRegistry {
    let definitions = actions::action_definitions();
    ActionRegistry::new(
        definitions,
        actions::KIND_ALIASES.to_vec(),
        actions::REQUIRED_ACTION_TYPES,
    )
}
