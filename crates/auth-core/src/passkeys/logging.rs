/// Upstream trace/debug events include ceremony state and credential payloads.
/// These calls are synchronous: a scoped empty dispatcher suppresses only their
/// events and restores the caller's dispatcher before returning. Never use this
/// around a future or task spawn, where the work could escape the scope.
pub(super) fn without_payload_events<T>(operation: impl FnOnce() -> T) -> T {
    tracing::dispatcher::with_default(&tracing::Dispatch::none(), operation)
}

#[cfg(test)]
mod tests {
    use crate::{PasskeyRegistrationResponse, PasskeyService};
    use std::fmt::Write;
    use std::sync::{Arc, Mutex};
    use tracing::{Event, Metadata, Subscriber, field::Visit, span};
    use uuid::Uuid;

    struct Recorder(Arc<Mutex<String>>);
    struct Fields<'a>(&'a mut String);
    impl Visit for Fields<'_> {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            write!(self.0, "{field}={value:?};").unwrap();
        }
    }
    impl Subscriber for Recorder {
        fn enabled(&self, _: &Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
            span::Id::from_u64(1)
        }
        fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
        fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}
        fn enter(&self, _: &span::Id) {}
        fn exit(&self, _: &span::Id) {}
        fn event(&self, event: &Event<'_>) {
            event.record(&mut Fields(&mut self.0.lock().unwrap()));
        }
    }

    #[test]
    fn suppresses_actual_upstream_payload_events_and_restores_caller_logging() {
        let service = PasskeyService::new("https://login.example.com", "Example").unwrap();
        let response: PasskeyRegistrationResponse = serde_json::from_value(serde_json::json!({
            "id": "private-ceremony-marker", "rawId": "AQ", "type": "public-key",
            "response": {"attestationObject": "AA", "clientDataJSON": "e30"}
        }))
        .unwrap();
        let (_, control) = service
            .begin_registration(Uuid::new_v4(), "label", &[])
            .unwrap();
        let output = Arc::new(Mutex::new(String::new()));
        tracing::subscriber::with_default(Recorder(output.clone()), || {
            // Positive control: the upstream release really emits the sensitive field at TRACE.
            let _ = service
                .verifier
                .finish_passkey_registration(&response, &control.state);
        });
        assert!(output.lock().unwrap().contains("private-ceremony-marker"));
        output.lock().unwrap().clear();
        tracing::subscriber::with_default(Recorder(output.clone()), || {
            tracing::info!("before-verification");
            let (_, state) = service
                .begin_registration(Uuid::new_v4(), "label", &[])
                .unwrap();
            assert!(service.verify_registration(&response, state).is_err());
            tracing::info!("after-verification");
        });
        let output = output.lock().unwrap();
        assert!(output.contains("before-verification"));
        assert!(output.contains("after-verification"));
        assert!(!output.contains("private-ceremony-marker"));
        assert!(!output.contains("client_data_json"));
        assert!(!output.contains("RegistrationState"));
    }
}
