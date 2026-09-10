#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestEnvelope<T> {
    pub request_id: String,
    pub payload: T,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseStatus {
    Ok,
    Rejected,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseEnvelope<T> {
    pub request_id: String,
    pub status: ResponseStatus,
    pub payload: Option<T>,
    pub message: Option<String>,
}
