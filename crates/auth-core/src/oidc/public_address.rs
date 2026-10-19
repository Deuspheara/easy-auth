use ipnet::IpNet;
use std::{net::IpAddr, sync::OnceLock};

// Conservative outbound policy, not a general routing oracle. IANA special-use
// registries reviewed 2026-10-19; transition/assignment ranges are denied as a whole.
// In particular, accepting all of 2000::/3 would admit documentation/transition IPs.
const DENIED_PREFIXES: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.88.99.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "2001::/23",
    "2001:db8::/32",
    "2002::/16",
    "3fff::/20",
];

pub(super) fn allowed(address: IpAddr) -> bool {
    static DENIED: OnceLock<Vec<IpNet>> = OnceLock::new();
    let denied = DENIED.get_or_init(|| {
        DENIED_PREFIXES
            .iter()
            .map(|prefix| prefix.parse().expect("fixed reviewed egress prefix"))
            .collect()
    });
    if let IpAddr::V6(address) = address {
        // Excludes mapped/compatible IPv4, NAT64, ULA, link-local, multicast and
        // unallocated space. There is no private-network development fallback.
        if address.segments()[0] & 0xe000 != 0x2000 {
            return false;
        }
    }
    !denied.iter().any(|network| network.contains(&address))
}
