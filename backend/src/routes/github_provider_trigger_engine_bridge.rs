use crate::routes::github_provider_trigger_execution_context::ProviderTriggerExecutionContext;
use async_trait::async_trait;

#[async_trait]
#[allow(dead_code)]
pub trait ProviderTriggerExecutor: Send + Sync {
    async fn execute_trigger(&self, context: &ProviderTriggerExecutionContext);
}

pub struct ProviderTriggerEngineBridge;

impl Default for ProviderTriggerEngineBridge {
    fn default() -> Self {
        Self::new()
    }
}

impl ProviderTriggerEngineBridge {
    pub fn new() -> Self {
        Self
    }

    pub async fn execute<E: ProviderTriggerExecutor>(
        &self,
        executor: &E,
        contexts: Vec<ProviderTriggerExecutionContext>,
    ) {
        for context in contexts {
            executor.execute_trigger(&context).await;
        }
    }
}
