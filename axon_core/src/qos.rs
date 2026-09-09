use std::time::Duration;

pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 65536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reliability {
    BestEffort,
    Reliable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Durability {
    Volatile,
    TransientLocal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryKind {
    KeepLast { depth: usize },
    KeepAll,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Liveliness {
    #[default]
    Automatic,
    ManualByTopic,
    ManualByParticipant,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QosProfile {
    pub reliability: Reliability,
    pub durability: Durability,
    pub history: HistoryKind,
    pub bandwidth_limit: Option<usize>,
    pub max_message_size: usize,
    pub deadline: Option<Duration>,
    pub lifespan: Option<Duration>,
    pub liveliness: Liveliness,
    pub liveliness_lease_duration: Option<Duration>,
}

impl QosProfile {
    pub fn default_sensor() -> Self {
        Self {
            reliability: Reliability::BestEffort,
            durability: Durability::Volatile,
            history: HistoryKind::KeepLast { depth: 5 },
            bandwidth_limit: None,
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            deadline: None,
            lifespan: None,
            liveliness: Liveliness::Automatic,
            liveliness_lease_duration: None,
        }
    }

    pub fn default_command() -> Self {
        Self {
            reliability: Reliability::Reliable,
            durability: Durability::Volatile,
            history: HistoryKind::KeepLast { depth: 1 },
            bandwidth_limit: None,
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            deadline: None,
            lifespan: None,
            liveliness: Liveliness::Automatic,
            liveliness_lease_duration: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoteQos {
    pub reliability: Reliability,
    pub durability: Durability,
    pub history: HistoryKind,
    pub deadline: Duration,
    pub lifespan: Duration,
    pub liveliness: Liveliness,
    pub liveliness_lease_duration: Duration,
    pub avoid_ros_namespace_conventions: bool,
}

impl From<RemoteQos> for QosProfile {
    fn from(rq: RemoteQos) -> Self {
        QosProfile {
            reliability: rq.reliability,
            durability: rq.durability,
            history: rq.history,
            bandwidth_limit: None,
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            deadline: if rq.deadline == Duration::from_secs(0) {
                None
            } else {
                Some(rq.deadline)
            },
            lifespan: if rq.lifespan == Duration::from_secs(0) {
                None
            } else {
                Some(rq.lifespan)
            },
            liveliness: rq.liveliness,
            liveliness_lease_duration: if rq.liveliness_lease_duration == Duration::from_secs(0) {
                None
            } else {
                Some(rq.liveliness_lease_duration)
            },
        }
    }
}

impl RemoteQos {
    pub fn from_qos_profile(qos: &QosProfile) -> Self {
        Self {
            reliability: qos.reliability,
            durability: qos.durability,
            history: qos.history,
            deadline: qos.deadline.unwrap_or(Duration::from_secs(0)),
            lifespan: qos.lifespan.unwrap_or(Duration::from_secs(0)),
            liveliness: qos.liveliness,
            liveliness_lease_duration: qos
                .liveliness_lease_duration
                .unwrap_or(Duration::from_secs(0)),
            avoid_ros_namespace_conventions: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QosHints {
    pub reliability: Reliability,
    pub durability: Durability,
    pub history: HistoryKind,
    pub lifespan: Option<Duration>,
    pub bandwidth_limit: Option<usize>,
    pub max_message_size: usize,
}

impl QosHints {
    pub fn from_qos_profile(qos: &QosProfile) -> Self {
        Self {
            reliability: qos.reliability,
            durability: qos.durability,
            history: qos.history,
            lifespan: qos.lifespan,
            bandwidth_limit: qos.bandwidth_limit,
            max_message_size: qos.max_message_size,
        }
    }
}

pub fn qos_profiles_compatible(pub_qos: &QosProfile, sub_qos: &QosProfile) -> bool {
    if pub_qos.reliability == Reliability::BestEffort
        && sub_qos.reliability == Reliability::Reliable
    {
        return false;
    }
    if sub_qos.durability == Durability::TransientLocal
        && pub_qos.durability == Durability::Volatile
    {
        return false;
    }
    // KeepLast depth controls each endpoint's local queue capacity. It is not
    // a requested/offered compatibility policy.
    if let (Some(pub_dl), Some(sub_dl)) = (pub_qos.deadline, sub_qos.deadline) {
        if pub_dl > sub_dl {
            return false;
        }
    }
    if sub_qos.liveliness == Liveliness::ManualByTopic
        && pub_qos.liveliness == Liveliness::Automatic
    {
        return false;
    }
    if sub_qos.liveliness == Liveliness::ManualByParticipant
        && pub_qos.liveliness != Liveliness::ManualByParticipant
    {
        return false;
    }
    if let (Some(pub_ls), Some(sub_ls)) = (pub_qos.lifespan, sub_qos.lifespan) {
        if pub_ls < sub_ls {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_qos() {
        let sensor = QosProfile::default_sensor();
        assert_eq!(sensor.reliability, Reliability::BestEffort);
        assert_eq!(sensor.history, HistoryKind::KeepLast { depth: 5 });

        let cmd = QosProfile::default_command();
        assert_eq!(cmd.reliability, Reliability::Reliable);
    }

    #[test]
    fn test_qos_with_deadline_and_lifespan() {
        let qos = QosProfile {
            deadline: Some(Duration::from_millis(100)),
            lifespan: Some(Duration::from_secs(1)),
            liveliness: Liveliness::ManualByTopic,
            liveliness_lease_duration: Some(Duration::from_secs(5)),
            ..QosProfile::default_sensor()
        };
        assert_eq!(qos.deadline, Some(Duration::from_millis(100)));
        assert_eq!(qos.lifespan, Some(Duration::from_secs(1)));
        assert_eq!(qos.liveliness, Liveliness::ManualByTopic);
        assert_eq!(qos.liveliness_lease_duration, Some(Duration::from_secs(5)));
    }

    #[test]
    fn test_qos_custom_resource_fields() {
        let qos = QosProfile {
            reliability: Reliability::BestEffort,
            durability: Durability::Volatile,
            history: HistoryKind::KeepLast { depth: 10 },
            bandwidth_limit: Some(50_000_000),
            max_message_size: 4096,
            deadline: None,
            lifespan: Some(Duration::from_secs(5)),
            liveliness: Liveliness::Automatic,
            liveliness_lease_duration: None,
        };
        assert_eq!(qos.bandwidth_limit, Some(50_000_000));
        assert_eq!(qos.max_message_size, 4096);
        assert_eq!(qos.history, HistoryKind::KeepLast { depth: 10 });
        assert_eq!(qos.deadline, None);
        assert_eq!(qos.lifespan, Some(Duration::from_secs(5)));
        assert_eq!(qos.liveliness, Liveliness::Automatic);
        assert_eq!(qos.liveliness_lease_duration, None);
    }

    #[test]
    fn test_qos_defaults_unlimited_bandwidth() {
        let sensor = QosProfile::default_sensor();
        assert_eq!(sensor.bandwidth_limit, None);
        assert_eq!(sensor.max_message_size, DEFAULT_MAX_MESSAGE_SIZE);

        let cmd = QosProfile::default_command();
        assert_eq!(cmd.bandwidth_limit, None);
        assert_eq!(cmd.max_message_size, DEFAULT_MAX_MESSAGE_SIZE);
    }

    #[test]
    fn test_remote_qos_conversion() {
        let rq = RemoteQos {
            reliability: Reliability::Reliable,
            durability: Durability::TransientLocal,
            history: HistoryKind::KeepLast { depth: 42 },
            deadline: Duration::from_secs(0),
            lifespan: Duration::from_secs(0),
            liveliness: Liveliness::Automatic,
            liveliness_lease_duration: Duration::from_secs(0),
            avoid_ros_namespace_conventions: false,
        };
        let qp: QosProfile = rq.into();
        assert_eq!(qp.reliability, Reliability::Reliable);
        assert_eq!(qp.durability, Durability::TransientLocal);
        assert_eq!(qp.history, HistoryKind::KeepLast { depth: 42 });
        assert_eq!(qp.bandwidth_limit, None);
        assert_eq!(qp.max_message_size, DEFAULT_MAX_MESSAGE_SIZE);
        assert_eq!(qp.deadline, None);
        assert_eq!(qp.lifespan, None);
        assert_eq!(qp.liveliness, Liveliness::Automatic);
        assert_eq!(qp.liveliness_lease_duration, None);
    }

    #[test]
    fn test_liveliness_default() {
        assert_eq!(Liveliness::default(), Liveliness::Automatic);
    }

    #[test]
    fn test_from_qos_profile_constructor() {
        let qp = QosProfile::default_sensor();
        let rq = RemoteQos::from_qos_profile(&qp);
        assert_eq!(rq.reliability, qp.reliability);
        assert_eq!(rq.durability, qp.durability);
        assert_eq!(rq.history, qp.history);
        assert_eq!(rq.deadline, Duration::from_secs(0));
        assert_eq!(rq.lifespan, Duration::from_secs(0));
        assert_eq!(rq.liveliness, Liveliness::Automatic);
        assert_eq!(rq.liveliness_lease_duration, Duration::from_secs(0));
        assert!(!rq.avoid_ros_namespace_conventions);
    }

    fn mq(
        reliability: Reliability,
        durability: Durability,
        history: HistoryKind,
        deadline: Option<Duration>,
        lifespan: Option<Duration>,
        liveliness: Liveliness,
    ) -> QosProfile {
        QosProfile {
            reliability,
            durability,
            history,
            bandwidth_limit: None,
            max_message_size: 1024,
            deadline,
            lifespan,
            liveliness,
            liveliness_lease_duration: None,
        }
    }

    #[test]
    fn best_effort_pub_reliable_sub_incompatible() {
        assert!(!qos_profiles_compatible(
            &mq(
                Reliability::BestEffort,
                Durability::Volatile,
                HistoryKind::KeepLast { depth: 10 },
                None,
                None,
                Liveliness::Automatic
            ),
            &mq(
                Reliability::Reliable,
                Durability::Volatile,
                HistoryKind::KeepLast { depth: 10 },
                None,
                None,
                Liveliness::Automatic
            ),
        ));
    }

    #[test]
    fn volatile_pub_transient_local_sub_incompatible() {
        assert!(!qos_profiles_compatible(
            &mq(
                Reliability::Reliable,
                Durability::Volatile,
                HistoryKind::KeepLast { depth: 10 },
                None,
                None,
                Liveliness::Automatic
            ),
            &mq(
                Reliability::Reliable,
                Durability::TransientLocal,
                HistoryKind::KeepLast { depth: 10 },
                None,
                None,
                Liveliness::Automatic
            ),
        ));
    }

    #[test]
    fn keep_last_depth_mismatch_compatible() {
        assert!(qos_profiles_compatible(
            &mq(
                Reliability::Reliable,
                Durability::Volatile,
                HistoryKind::KeepLast { depth: 5 },
                None,
                None,
                Liveliness::Automatic
            ),
            &mq(
                Reliability::Reliable,
                Durability::Volatile,
                HistoryKind::KeepLast { depth: 10 },
                None,
                None,
                Liveliness::Automatic
            ),
        ));
    }

    #[test]
    fn deadline_pub_longer_than_sub_incompatible() {
        assert!(!qos_profiles_compatible(
            &mq(
                Reliability::Reliable,
                Durability::Volatile,
                HistoryKind::KeepLast { depth: 10 },
                Some(Duration::from_secs(5)),
                None,
                Liveliness::Automatic
            ),
            &mq(
                Reliability::Reliable,
                Durability::Volatile,
                HistoryKind::KeepLast { depth: 10 },
                Some(Duration::from_secs(2)),
                None,
                Liveliness::Automatic
            ),
        ));
    }

    #[test]
    fn matching_qos_is_compatible() {
        let q = mq(
            Reliability::Reliable,
            Durability::Volatile,
            HistoryKind::KeepLast { depth: 10 },
            Some(Duration::from_secs(1)),
            Some(Duration::from_secs(10)),
            Liveliness::Automatic,
        );
        assert!(qos_profiles_compatible(&q, &q));
    }

    #[test]
    fn manual_by_topic_sub_automatic_pub_incompatible() {
        assert!(!qos_profiles_compatible(
            &mq(
                Reliability::Reliable,
                Durability::Volatile,
                HistoryKind::KeepLast { depth: 10 },
                None,
                None,
                Liveliness::Automatic
            ),
            &mq(
                Reliability::Reliable,
                Durability::Volatile,
                HistoryKind::KeepLast { depth: 10 },
                None,
                None,
                Liveliness::ManualByTopic
            ),
        ));
    }

    #[test]
    fn lifespan_pub_shorter_than_sub_incompatible() {
        assert!(!qos_profiles_compatible(
            &mq(
                Reliability::Reliable,
                Durability::Volatile,
                HistoryKind::KeepLast { depth: 10 },
                None,
                Some(Duration::from_secs(5)),
                Liveliness::Automatic
            ),
            &mq(
                Reliability::Reliable,
                Durability::Volatile,
                HistoryKind::KeepLast { depth: 10 },
                None,
                Some(Duration::from_secs(10)),
                Liveliness::Automatic
            ),
        ));
    }

    #[test]
    fn best_effort_both_sides_compatible() {
        let q = mq(
            Reliability::BestEffort,
            Durability::Volatile,
            HistoryKind::KeepLast { depth: 10 },
            None,
            None,
            Liveliness::Automatic,
        );
        assert!(qos_profiles_compatible(&q, &q));
    }

    #[test]
    fn keep_all_both_sides_compatible() {
        let q = mq(
            Reliability::Reliable,
            Durability::Volatile,
            HistoryKind::KeepAll,
            None,
            None,
            Liveliness::Automatic,
        );
        assert!(qos_profiles_compatible(&q, &q));
    }
}
