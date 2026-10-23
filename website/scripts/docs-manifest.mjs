// Only named, committed public guides enter the site. Never glob docs/security.
export const guides = [
  {
    source: "docs/guides/server-cli.md",
    slug: "server-configuration",
    title: "Server configuration",
  },
  { source: "docs/guides/passwords.md", slug: "passwords", title: "Passwords" },
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
