//! Fixed, credential-free request observations through boundary response/drop.
use axum::http::StatusCode;
use std::time::Instant;
use tracing::Dispatch;
use uuid::Uuid;

pub(super) enum Completion {
    Response,
    TimedOut,
}

pub(super) struct Observation {
    request_id: String,
    started: Instant,
    dispatcher: Dispatch,
    completed: bool,
}

impl Observation {
    pub(super) fn start() -> Self {
        Self {
            request_id: Uuid::new_v4().to_string(),
            started: Instant::now(),
            // A future may be dropped outside its last poll's subscriber scope.
            // Keep this request's original sink for its cancellation observation.
            dispatcher: tracing::dispatcher::get_default(Clone::clone),
            completed: false,
        }
    }

    pub(super) fn request_id(&self) -> &str {
        &self.request_id
    }

    pub(super) fn complete(mut self, status: StatusCode, completion: Completion) {
        self.completed = true;
        let completion = match completion {
            Completion::Response => "response",
            Completion::TimedOut => "timed_out",
        };
        tracing::dispatcher::with_default(&self.dispatcher, || {
            tracing::info!(
                target: "easy_auth_axum::browser::boundary",
                request_id = self.request_id,
                status = status.as_u16(),
                duration_micros = self.duration_micros(),
                completion,
                "http_request_completed"
            );
        });
    }

    fn duration_micros(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_micros()).unwrap_or(u64::MAX)
    }
}

impl Drop for Observation {
    fn drop(&mut self) {
        if !self.completed {
            tracing::dispatcher::with_default(&self.dispatcher, || {
                tracing::info!(
                    target: "easy_auth_axum::browser::boundary",
                    request_id = self.request_id,
                    duration_micros = self.duration_micros(),
                    completion = "cancelled",
                    "http_request_cancelled"
                );
            });
        }
    }
}
