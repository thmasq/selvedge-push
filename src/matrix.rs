use std::borrow::Cow;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

fn deserialize_lenient<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    Ok(serde_json::from_value(value).ok())
}

fn deserialize_lenient_bool<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(deserialize_lenient::<_, bool>(deserializer)?.unwrap_or(false))
}

/// Matrix Push Gateway API v1 request body (`POST /_matrix/push/v1/notify`).
#[derive(Debug, Deserialize)]
pub struct NotifyRequest {
    pub notification: Notification,
}

#[derive(Debug, Deserialize)]
pub struct Notification {
    pub event_id: Option<String>,
    pub room_id: Option<String>,
    #[serde(default, deserialize_with = "deserialize_lenient")]
    pub counts: Option<NotificationCounts>,
    #[serde(default)]
    pub devices: Vec<Device>,
}

#[derive(Debug, Default, Deserialize)]
pub struct NotificationCounts {
    #[serde(default, deserialize_with = "deserialize_lenient")]
    pub unread: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct Device {
    pub app_id: String,
    pub pushkey: String,
    pub data: Option<DeviceData>,
    #[serde(default, deserialize_with = "deserialize_lenient")]
    pub tweaks: Option<DeviceTweaks>,
}

#[derive(Debug, Default, Deserialize)]
pub struct DeviceTweaks {
    #[serde(default, deserialize_with = "deserialize_lenient")]
    pub highlight: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct DeviceData {
    pub p256dh: Option<String>,
    pub auth: Option<String>,
    /// Rolling-window debounce duration in milliseconds (`0` or omitted = disabled).
    #[serde(default, deserialize_with = "deserialize_lenient")]
    pub debounce_ms: Option<u64>,
    /// Optional Do-Not-Disturb schedule evaluated against UTC clock.
    #[serde(default, deserialize_with = "deserialize_lenient")]
    pub quiet_hours: Option<QuietHours>,
    /// When `true`, notifications with `tweaks.highlight == Some(true)` bypass debouncing.
    #[serde(default, deserialize_with = "deserialize_lenient_bool")]
    pub bypass_debounce_on_highlight: bool,
}

/// Do-Not-Disturb window stored in `pusher.data.quiet_hours`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct QuietHours {
    /// Start minute of local day (`0..1440`).
    pub start_min: u16,
    /// End minute of local day (`0..1440`).
    pub end_min: u16,
    /// Offset from UTC in minutes (e.g. `-180` for UTC-3, `330` for UTC+5:30).
    pub tz_offset_min: i16,
}

impl QuietHours {
    /// Returns `true` if the schedule parameters are within valid bounds.
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.start_min < 1440
            && self.end_min < 1440
            && self.start_min != self.end_min
            && self.tz_offset_min >= -720
            && self.tz_offset_min <= 840
    }

    /// Evaluates whether the current wall-clock UTC time falls inside this quiet window.
    #[must_use]
    pub fn is_active_now(self) -> bool {
        self.is_active_at(SystemTime::now())
    }

    /// Evaluates whether `now` falls inside this quiet window.
    #[must_use]
    pub fn is_active_at(self, now: SystemTime) -> bool {
        let Ok(since_epoch) = now.duration_since(UNIX_EPOCH) else {
            return false;
        };
        let utc_min_of_day = ((since_epoch.as_secs() / 60) % 1440) as u16;
        self.is_active_at_utc_minute(utc_min_of_day)
    }

    /// Evaluates whether `utc_min_of_day` (`0..1440`) falls inside this quiet window.
    #[must_use]
    pub fn is_active_at_utc_minute(self, utc_min_of_day: u16) -> bool {
        if !self.is_valid() {
            return false;
        }
        let local_min =
            (i32::from(utc_min_of_day % 1440) + i32::from(self.tz_offset_min)).rem_euclid(1440);
        let start = i32::from(self.start_min);
        let end = i32::from(self.end_min);

        if start < end {
            local_min >= start && local_min < end
        } else {
            // Wraps across midnight (e.g. 22:00..07:00)
            local_min >= start || local_min < end
        }
    }
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
    pub body: Cow<'static, str>,
    pub navigate: &'a str,
    pub mutable: bool,
    pub tag: &'a str,
    pub data: DeclarativeNotificationData<'a>,
}

#[derive(Debug, Serialize)]
pub struct DeclarativeNotificationData<'a> {
    pub room_id: &'a str,
    pub event_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<u32>,
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
            body: Cow::Borrowed("New message"),
            navigate,
            mutable: true,
            tag: event_id,
            data: DeclarativeNotificationData {
                room_id,
                event_id,
                count: None,
            },
        },
    }
}

#[must_use]
pub fn build_coalesced_declarative_payload<'a>(
    navigate: &'a str,
    room_id: &'a str,
    event_id: &'a str,
    count: u32,
) -> DeclarativePushPayload<'a> {
    if count <= 1 {
        return build_declarative_payload(navigate, room_id, event_id);
    }

    DeclarativePushPayload {
        web_push: 8030,
        notification: DeclarativeNotification {
            title: "Selvedge",
            body: Cow::Owned(format!("{count} new messages")),
            navigate,
            mutable: true,
            tag: room_id,
            data: DeclarativeNotificationData {
                room_id,
                event_id,
                count: Some(count),
            },
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
        assert!(value["notification"]["data"].get("count").is_none());
    }

    #[test]
    fn coalesced_payload_sets_count_body_and_room_tag() {
        let payload = build_coalesced_declarative_payload(
            "https://selvedge.example.com/",
            "!room1:example.org",
            "$event5",
            5,
        );
        let value = serde_json::to_value(&payload).unwrap();

        assert_eq!(value["notification"]["body"], "5 new messages");
        assert_eq!(value["notification"]["tag"], "!room1:example.org");
        assert_eq!(value["notification"]["data"]["event_id"], "$event5");
        assert_eq!(value["notification"]["data"]["count"], 5);
    }

    #[test]
    fn quiet_hours_handles_same_day_overnight_and_tz_offsets() {
        // 13:00..17:00 UTC
        let daytime = QuietHours {
            start_min: 13 * 60,
            end_min: 17 * 60,
            tz_offset_min: 0,
        };
        assert!(!daytime.is_active_at_utc_minute(12 * 60 + 59));
        assert!(daytime.is_active_at_utc_minute(13 * 60));
        assert!(daytime.is_active_at_utc_minute(16 * 60 + 59));
        assert!(!daytime.is_active_at_utc_minute(17 * 60));

        // 22:00..07:00 local in UTC-3 (-180 min): 01:00..10:00 UTC
        let overnight = QuietHours {
            start_min: 22 * 60,
            end_min: 7 * 60,
            tz_offset_min: -180,
        };
        assert!(!overnight.is_active_at_utc_minute(59)); // 21:59 local (00:59 UTC)
        assert!(overnight.is_active_at_utc_minute(60)); // 22:00 local (01:00 UTC)
        assert!(overnight.is_active_at_utc_minute(9 * 60 + 59)); // 06:59 local
        assert!(!overnight.is_active_at_utc_minute(10 * 60)); // 07:00 local

        // Invalid ranges are never active
        let invalid = QuietHours {
            start_min: 60,
            end_min: 60,
            tz_offset_min: 0,
        };
        assert!(!invalid.is_active_at_utc_minute(60));
    }

    #[test]
    fn lenient_deserialization_tolerates_null_and_wrong_types() {
        let raw = serde_json::json!({
            "notification": {
                "event_id": "$e1",
                "room_id": "!r1:example.org",
                "counts": { "unread": "not-a-number" },
                "devices": [{
            "app_id": "org.selvedge.web",
                    "pushkey": "https://fcm.googleapis.com/fcm/send/abc",
            "tweaks": { "highlight": "yes" },
            "data": {
                        "p256dh": "key",
                        "auth": "secret",
                        "debounce_ms": "3000",
                        "quiet_hours": {},
                        "bypass_debounce_on_highlight": null
            }
                }]
            }
        });

        let req: NotifyRequest = serde_json::from_value(raw).unwrap();
        assert_eq!(req.notification.counts.unwrap().unread, None);
        let dev = &req.notification.devices[0];
        assert_eq!(dev.tweaks.as_ref().unwrap().highlight, None);
        let data = dev.data.as_ref().unwrap();
        assert_eq!(data.debounce_ms, None);
        assert_eq!(data.quiet_hours, None);
        assert!(!data.bypass_debounce_on_highlight);
    }

    #[test]
    fn quiet_hours_validates_tz_and_minute_bounds() {
        assert!(
            QuietHours {
                start_min: 0,
                end_min: 1439,
                tz_offset_min: -720,
            }
            .is_valid()
        );
        assert!(
            QuietHours {
                start_min: 0,
                end_min: 1439,
                tz_offset_min: 840,
            }
            .is_valid()
        );
        for bad in [
            QuietHours {
                start_min: 1440,
                end_min: 60,
                tz_offset_min: 0,
            },
            QuietHours {
                start_min: 60,
                end_min: 1440,
                tz_offset_min: 0,
            },
            QuietHours {
                start_min: 0,
                end_min: 60,
                tz_offset_min: -721,
            },
            QuietHours {
                start_min: 0,
                end_min: 60,
                tz_offset_min: 841,
            },
        ] {
            assert!(!bad.is_valid());
            assert!(!bad.is_active_at_utc_minute(30));
        }
    }
}
