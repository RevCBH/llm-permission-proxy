use std::collections::HashMap;

use once_cell::sync::Lazy;

use crate::models::{OperationCatalogEntry, PermissionLevel, RiskTier};

static OPERATION_CATALOG: Lazy<HashMap<&'static str, OperationCatalogEntry>> = Lazy::new(|| {
    let mut map = HashMap::new();

    map.insert(
        "dns.record.read",
        OperationCatalogEntry {
            operation_id: "dns.record.read",
            required_level: PermissionLevel::Read,
            risk_tier: RiskTier::Safe,
        },
    );
    map.insert(
        "dns.record.write",
        OperationCatalogEntry {
            operation_id: "dns.record.write",
            required_level: PermissionLevel::Write,
            risk_tier: RiskTier::Elevated,
        },
    );
    map.insert(
        "cache.purge.execute",
        OperationCatalogEntry {
            operation_id: "cache.purge.execute",
            required_level: PermissionLevel::Write,
            risk_tier: RiskTier::Elevated,
        },
    );
    map.insert(
        "workers.deploy.write",
        OperationCatalogEntry {
            operation_id: "workers.deploy.write",
            required_level: PermissionLevel::Write,
            risk_tier: RiskTier::Sensitive,
        },
    );
    map.insert(
        "waf.rules.read",
        OperationCatalogEntry {
            operation_id: "waf.rules.read",
            required_level: PermissionLevel::Read,
            risk_tier: RiskTier::Safe,
        },
    );
    map.insert(
        "waf.rules.write",
        OperationCatalogEntry {
            operation_id: "waf.rules.write",
            required_level: PermissionLevel::Write,
            risk_tier: RiskTier::Sensitive,
        },
    );
    map.insert(
        "ssl.mode.write",
        OperationCatalogEntry {
            operation_id: "ssl.mode.write",
            required_level: PermissionLevel::Admin,
            risk_tier: RiskTier::Sensitive,
        },
    );
    map
});

pub fn operation_catalog_entry(operation_id: &str) -> Option<OperationCatalogEntry> {
    OPERATION_CATALOG.get(operation_id).cloned()
}

pub fn is_sensitive_risk(operation_id: &str) -> bool {
    operation_catalog_entry(operation_id)
        .map(|entry| entry.risk_tier == RiskTier::Sensitive)
        .unwrap_or(false)
}

pub fn all_catalog_operations() -> Vec<&'static str> {
    OPERATION_CATALOG.keys().copied().collect()
}

#[cfg(test)]
mod tests {
    use super::{all_catalog_operations, is_sensitive_risk, operation_catalog_entry};
    use crate::models::{PermissionLevel, RiskTier};

    #[test]
    fn lookup_returns_expected_entry() {
        let entry = operation_catalog_entry("dns.record.write").expect("entry should exist");
        assert_eq!(entry.required_level, PermissionLevel::Write);
        assert_eq!(entry.risk_tier, RiskTier::Elevated);
    }

    #[test]
    fn sensitive_classification_matches_catalog() {
        assert!(is_sensitive_risk("workers.deploy.write"));
        assert!(!is_sensitive_risk("dns.record.read"));
    }

    #[test]
    fn catalog_contains_required_core_operations() {
        let all = all_catalog_operations();
        assert!(all.contains(&"dns.record.read"));
        assert!(all.contains(&"cache.purge.execute"));
        assert!(!all.contains(&"permissions.admin"));
    }
}
