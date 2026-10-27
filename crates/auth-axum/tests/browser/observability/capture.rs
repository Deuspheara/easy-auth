//! Capture fixed browser observation fields without installing a global sink.
use serde_json::{Map, Value, json};
use std::sync::{Arc, Mutex};
use tracing::{
    Dispatch, Event, Metadata, Subscriber,
    field::{Field, Visit},
    span,
};

#[derive(Clone, Default)]
pub(super) struct Capture(Arc<Mutex<Vec<Map<String, Value>>>>);

impl Capture {
    pub(super) fn dispatcher(&self) -> Dispatch {
        Dispatch::new(self.clone())
    }

    pub(super) fn events(&self) -> Vec<Map<String, Value>> {
        self.0.lock().unwrap().clone()
    }
}

struct Fields(Map<String, Value>);
impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0
            .insert(field.name().into(), json!(format!("{value:?}")));
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().into(), json!(value));
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0.insert(field.name().into(), json!(value));
    }
}

impl Subscriber for Capture {
    fn register_callsite(&self, _: &'static Metadata<'static>) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::sometimes()
    }
    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::TRACE)
    }
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.is_event() && metadata.target().starts_with("easy_auth_axum::browser::")
    }
    fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }
    fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
    fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}
    fn enter(&self, _: &span::Id) {}
    fn exit(&self, _: &span::Id) {}
    fn event(&self, event: &Event<'_>) {
        let mut fields = Fields(Map::new());
        event.record(&mut fields);
        self.0.lock().unwrap().push(fields.0);
    }
}
