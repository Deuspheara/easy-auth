// Serve this module from your application's origin, never from the docs website.
export type PublicUser = {
  id: string;
  realm_id: string;
  email: string | null;
  display_name: string | null;
  authentication_policy: "mailbox" | "passkey_required" | "provider_required";
};

const options = {
  credentials: "same-origin",
  cache: "no-store",
  redirect: "error",
} as const;

export async function currentUser(): Promise<PublicUser | null> {
  const response = await fetch("/v1/session", options);
  if (response.status === 401) return null;
  if (response.status !== 200) throw new Error("Session lookup unavailable");
  const value: unknown = await response.json();
  if (!isPublicUser(value)) throw new Error("Unexpected public user response");
  return value;
}

function isPublicUser(value: unknown): value is PublicUser {
  if (value === null || typeof value !== "object") return false;
  const user = value as Record<string, unknown>;
  return (
    typeof user.id === "string" &&
    typeof user.realm_id === "string" &&
    (user.email === null || typeof user.email === "string") &&
    (user.display_name === null || typeof user.display_name === "string") &&
    typeof user.authentication_policy === "string" &&
    ["mailbox", "passkey_required", "provider_required"].includes(
      user.authentication_policy,
    )
  );
}

export async function requestEmail(
  email: string,
): Promise<"accepted" | "limited"> {
  const response = await fetch("/v1/email/start", {
    ...options,
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
  });
  if (response.status === 202) return "accepted";
  if (response.status === 429) return "limited";
  throw new Error("Sign-in request unavailable");
}

export async function signOut(): Promise<void> {
  const response = await fetch("/v1/logout", { ...options, method: "POST" });
  if (response.status !== 204) throw new Error("Sign-out unavailable");
}
