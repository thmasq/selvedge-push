use serde::{Deserialize, Serialize};

/// Matrix Push Gateway API v1 request body (`POST /_matrix/push/v1/notify`).
#[derive(Debug, Deserialize)]
pub struct NotifyRequest {
    pub notification: Notification,
}

#[derive(Debug, Deserialize)]
pub struct Notification {
    pub event_id: Option<String>,
    pub room_id: Option<String>,
    #[serde(default)]
    pub devices: Vec<Device>,
}

#[derive(Debug, Deserialize)]
pub struct Device {
    pub app_id: String,
    pub pushkey: String,
    pub data: Option<DeviceData>,
}

#[derive(Debug, Deserialize)]
pub struct DeviceData {
    pub p256dh: Option<String>,
    pub auth: Option<String>,
}

/// Matrix Push Gateway API v1 response body.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NotifyResponse {
    pub rejected: Vec<String>,
}

/// Declarative Web Push payload (`web_push: 8030`, `mutable: true`).
#[derive(Debug, Serialize)]
pub struct DeclarativePushPayload<'a> {
    pub web_push: u16,
    pub notification: DeclarativeNotification<'a>,
}

#[derive(Debug, Serialize)]
pub struct DeclarativeNotification<'a> {
    pub title: &'static str,
    pub body: &'static str,
    pub navigate: &'a str,
    pub mutable: bool,
    pub tag: &'a str,
    pub data: DeclarativeNotificationData<'a>,
}

#[derive(Debug, Serialize)]
pub struct DeclarativeNotificationData<'a> {
    pub room_id: &'a str,
    pub event_id: &'a str,
}

#[must_use]
pub const fn build_declarative_payload<'a>(
    navigate: &'a str,
    room_id: &'a str,
    event_id: &'a str,
) -> DeclarativePushPayload<'a> {
    DeclarativePushPayload {
        web_push: 8030,
        notification: DeclarativeNotification {
            title: "Selvedge",
            body: "New message",
            navigate,
            mutable: true,
            tag: event_id,
            data: DeclarativeNotificationData { room_id, event_id },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declarative_payload_matches_spec_shape() {
        let payload = build_declarative_payload(
            "https://selvedge.example.com/",
            "!room1:example.org",
            "$event1",
        );
        let value = serde_json::to_value(&payload).unwrap();

        assert_eq!(value["web_push"], 8030);
        assert_eq!(value["notification"]["title"], "Selvedge");
        assert_eq!(value["notification"]["body"], "New message");
        assert_eq!(
            value["notification"]["navigate"],
            "https://selvedge.example.com/"
        );
        assert_eq!(value["notification"]["mutable"], true);
        assert_eq!(value["notification"]["tag"], "$event1");
        assert_eq!(
            value["notification"]["data"]["room_id"],
            "!room1:example.org"
        );
        assert_eq!(value["notification"]["data"]["event_id"], "$event1");
    }
}
