import { execFileSync } from "node:child_process";
import path from "node:path";

const commandOptions = {
  encoding: "utf8",
  stdio: ["ignore", "pipe", "ignore"],
};
// Astro bundles imported components before prerendering: import.meta.url is then
// inside dist, so resolve the repository through Git rather than the bundle path.
export const root = execFileSync("git", ["rev-parse", "--show-toplevel"], {
  ...commandOptions,
  cwd: process.cwd(),
}).trim();
export const website = path.join(root, "website");
export const git = (...args) =>
  execFileSync("git", args, { ...commandOptions, cwd: root });
export const revision = git("rev-parse", "HEAD").trim();
export const published = new Set(
  git("ls-tree", "-r", "--name-only", revision).trim().split("\n"),
);
