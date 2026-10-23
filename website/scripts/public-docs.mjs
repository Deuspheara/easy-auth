import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const website = fileURLToPath(new URL("../", import.meta.url));
export const root = path.resolve(website, "..");
export const git = (...args) =>
  execFileSync("git", args, {
    cwd: root,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  });
export const revision = git("rev-parse", "HEAD").trim();
export const published = new Set(
  git("ls-tree", "-r", "--name-only", revision).trim().split("\n"),
);
