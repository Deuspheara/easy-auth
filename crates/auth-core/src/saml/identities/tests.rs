use super::{SamlIdentityPolicy, SamlJitPolicy};
use crate::SamlRegistration;
use uuid::Uuid;

#[test]
fn identity_policy_requires_explicit_jit_and_retains_exact_registration() {
    let reg = SamlRegistration::unsigned_redirect(
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        "urn:example:sp",
        "urn:example:idp",
        "https://idp.example/sso",
        "https://sp.example/acs",
    )
    .unwrap();
    let policy = SamlIdentityPolicy::new(reg.clone());
    assert_eq!(policy.jit(), SamlJitPolicy::Deny);
    assert_eq!(policy.registration(), &reg);
    assert_eq!(SamlJitPolicy::default(), SamlJitPolicy::Deny);
    let allowed = policy.clone().with_jit(SamlJitPolicy::Allow);
    assert_eq!(allowed.jit(), SamlJitPolicy::Allow);
    assert_eq!(policy.jit(), SamlJitPolicy::Deny);
    assert_eq!(allowed.registration(), policy.registration());
    assert_ne!(policy, SamlIdentityPolicy::new(reg.reconfigured()));
}
