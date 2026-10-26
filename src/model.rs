#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct WatchEntry {
    pub domain: String,
    pub last_status: String,
}

#[derive(Debug, Clone, Default)]
pub struct DomainDates {
    pub registered: Option<String>,
    pub updated: Option<String>,
    pub expires: Option<String>,
}

#[derive(Debug, Clone)]
pub enum Availability {
    Available,
    Protected(ProtectionReason),
    Taken(DomainDates),
    Unknown(UnknownReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownReason {
    Inconclusive,
    Timeout,
    RateLimited,
    Unreachable,
    InvalidResponse,
    ServiceUnavailable,
    NoRegistryService,
    Cancelled,
    NotChecked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionReason { Reserved, Trademark }

impl ProtectionReason {
    pub fn label(self) -> &'static str {
        match self {
            Self::Reserved => "reserved / blocked",
            Self::Trademark => "trademark protected",
        }
    }
}

impl UnknownReason {
    pub fn label(self) -> &'static str {
        match self {
            Self::Inconclusive => "registry checks inconclusive",
            Self::Timeout => "registry timed out",
            Self::RateLimited => "registry rate limited",
            Self::Unreachable => "registry unreachable",
            Self::InvalidResponse => "invalid registry response",
            Self::ServiceUnavailable => "registry service unavailable",
            Self::NoRegistryService => "no supported registry service",
            Self::Cancelled => "check cancelled",
            Self::NotChecked => "not checked this session",
        }
    }

    // Keep an actionable registry failure when another source has no evidence.
    // This selects an observed reason; it never changes availability precedence.
    pub fn combine(self, other: Self) -> Self {
        let rank = |reason| match reason {
            Self::RateLimited => 8, Self::Timeout => 7, Self::Unreachable => 6,
            Self::InvalidResponse => 5, Self::ServiceUnavailable => 4,
            Self::NoRegistryService => 3, Self::Cancelled => 2,
            Self::NotChecked => 1, Self::Inconclusive => 0,
        };
        if rank(other) > rank(self) { other } else { self }
    }
}

impl Availability {
    pub fn as_str(&self) -> &'static str {
        match self {
            Availability::Available => "available",
            Availability::Protected(_) => "protected",
            Availability::Taken(_) => "taken",
            Availability::Unknown(_) => "unknown",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_inconclusive_reason_preserves_the_plain_status_contract() {
        for reason in [UnknownReason::Inconclusive, UnknownReason::Timeout, UnknownReason::RateLimited,
            UnknownReason::Unreachable, UnknownReason::InvalidResponse, UnknownReason::ServiceUnavailable,
            UnknownReason::NoRegistryService, UnknownReason::Cancelled, UnknownReason::NotChecked] {
            assert_eq!(format!("example.com {}", Availability::Unknown(reason).as_str()), "example.com unknown");
        }
    }
}
