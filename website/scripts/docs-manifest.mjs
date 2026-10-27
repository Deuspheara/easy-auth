// Only named, committed public guides enter the site. Never glob docs/security.
export const guides = [
  {
    source: "docs/guides/containers.md",
    slug: "containers",
    title: "Local containers",
  },
  {
    source: "docs/guides/backups.md",
    slug: "backups",
    title: "Backups and restore checks",
  },
  {
    source: "docs/guides/upgrades.md",
    slug: "upgrades",
    title: "Migration recovery and upgrades",
  },
  {
    source: "docs/guides/retention.md",
    slug: "retention",
    title: "Realm retention maintenance",
  },
  {
    source: "docs/guides/incident-recovery.md",
    slug: "incident-recovery",
    title: "Incident recovery and revocation",
  },
  {
    source: "docs/guides/minimal-clients.md",
    slug: "minimal-clients",
    title: "Minimal Rust and TypeScript",
  },
  {
    source: "docs/guides/setup-walkthrough.md",
    slug: "setup-walkthrough",
    title: "Setup walkthrough",
  },
  {
    source: "docs/guides/server-cli.md",
    slug: "server-configuration",
    title: "Server configuration",
  },
  {
    source: "docs/guides/database-roles.md",
    slug: "database-roles",
    title: "Database roles and migrations",
  },
  {
    source: "docs/guides/provider-setup.md",
    slug: "provider-setup",
    title: "Choose an integration",
  },
  {
    source: "docs/guides/issuer-standalone.md",
    slug: "issuer-standalone",
    title: "Explicit issuer setup",
  },
  {
    source: "docs/guides/custom-ui.md",
    slug: "custom-ui",
    title: "Custom UI",
  },
  {
    source: "docs/guides/apple-setup.md",
    slug: "apple-setup",
    title: "Apple prerequisites",
  },
  {
    source: "docs/guides/social-linking.md",
    slug: "social-linking",
    title: "Link provider accounts",
  },
  { source: "docs/guides/passwords.md", slug: "passwords", title: "Passwords" },
  {
    source: "docs/guides/authentication-performance.md",
    slug: "authentication-performance",
    title: "Local authentication measurements",
  },
  {
    source: "docs/guides/http-observability.md",
    slug: "http-observability",
    title: "HTTP observations and resource limits",
  },
  {
    source: "docs/guides/password-recovery.md",
    slug: "password-recovery",
    title: "Password recovery",
  },
  { source: "docs/guides/sessions.md", slug: "sessions", title: "Sessions" },
  {
    source: "docs/guides/account-lifecycle.md",
    slug: "account-lifecycle",
    title: "Account lifecycle",
  },
  { source: "docs/guides/oidc-web.md", slug: "oidc", title: "OpenID Connect" },
  {
    source: "docs/guides/google.md",
    slug: "google",
    title: "Google integration",
  },
  { source: "docs/guides/saml.md", slug: "saml", title: "SAML" },
  {
    source: "docs/guides/saml-release.md",
    slug: "saml-release",
    title: "SAML deployment",
  },
  {
    source: "docs/guides/passkey-enrollment.md",
    slug: "passkey-enrollment",
    title: "Passkey enrollment",
  },
  {
    source: "docs/guides/passkey-authentication.md",
    slug: "passkey-authentication",
    title: "Passkey sign-in",
  },
];
