export const features = [
  {
    name: "Email links",
    mark: "@",
    status: "Available",
    description: "Browser-bound email confirmation and server-side sessions.",
    href: "/docs/getting-started/",
    featured: true,
  },
  {
    name: "Passwords",
    mark: "＊",
    status: "Available",
    description:
      "Verified enrollment, Argon2id hashing and purpose-bound password recovery.",
    href: "/docs/guides/passwords/",
    featured: true,
  },
  {
    name: "Session control",
    mark: "↗",
    status: "Available",
    description:
      "List, revoke and expire sessions. Your application keeps control of authorization.",
    href: "/docs/guides/sessions/",
    featured: true,
  },
  {
    name: "OpenID Connect",
    mark: "◇",
    status: "Opt-in",
    description:
      "Connect a trusted provider with explicit issuer policy, PKCE and local identity mapping.",
    href: "/docs/guides/oidc/",
    featured: true,
  },
  {
    name: "SAML",
    mark: "⇄",
    status: "Opt-in",
    description:
      "SP-initiated sign-in with pinned IdP certificates, request correlation and durable replay protection.",
    href: "/docs/guides/saml/",
    featured: true,
  },
  {
    name: "Passkeys",
    mark: "⌘",
    status: "Experimental",
    description:
      "Registration and sign-in components with documented device and recovery limits.",
    href: "/docs/guides/passkey-enrollment/",
    featured: true,
  },
  {
    name: "Google",
    mark: "G",
    status: "Component",
    description:
      "Provider and native-browser integration components with separately documented acceptance scope.",
    href: "/docs/guides/google/",
    featured: false,
  },
  {
    name: "Apple",
    mark: "◦",
    status: "Component",
    description:
      "Experimental code/web flow, explicit linking and protected grant revocation. Real Apple acceptance and ordinary activation remain gated.",
    href: "/docs/guides/apple-setup/",
    featured: false,
  },
  {
    name: "Outbound OIDC issuer",
    mark: "→",
    status: "Not released",
    description:
      "Signed issuance, native refresh and introspection components have bounded owned-client evidence. Feature-complete release remains gated.",
    href: "/docs/features/",
    featured: false,
  },
] as const;
