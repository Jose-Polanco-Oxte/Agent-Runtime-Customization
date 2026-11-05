import fs from "node:fs";
import path from "node:path";

function requiredAbsolutePath(name: string, kind: "file" | "directory"): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is required`);
  }
  const resolved = path.resolve(value);
  if (!path.isAbsolute(resolved)) {
    throw new Error(`${name} must resolve to an absolute path`);
  }
  if (kind === "file" && !fs.statSync(resolved, { throwIfNoEntry: false })?.isFile()) {
    throw new Error(`${name} does not identify an existing file`);
  }
  if (kind === "directory") {
    fs.mkdirSync(resolved, { recursive: true });
  }
  return resolved;
}

const appBinary = requiredAbsolutePath("ARC_WEBDRIVER_BINARY", "file");
const outputDirectory = requiredAbsolutePath("ARC_WEBDRIVER_OUTPUT_DIR", "directory");
const terminalEvidence = path.join(outputDirectory, "terminal-attempts.log");
const tauriDriverPath = process.env.ARC_WEBDRIVER_TAURI_DRIVER;
process.env.ARC_WEBDRIVER_TERMINAL_EVIDENCE = terminalEvidence;

export const config: WebdriverIO.Config = {
  runner: "local",
  specs: ["./specs/readiness-acl.spec.ts"],
  maxInstances: 1,
  capabilities: [
    {
      browserName: "tauri",
      "tauri:options": {
        application: appBinary,
      },
    },
  ],
  services: [
    [
      "@wdio/tauri-service",
      {
        appBinaryPath: appBinary,
        driverProvider: "external",
        autoInstallTauriDriver: false,
        autoDownloadEdgeDriver: true,
        tauriDriverPath,
        tauriDriverPort: 4444,
        windowLabel: "decision",
        startTimeout: 60_000,
        commandTimeout: 30_000,
        logLevel: "info",
      },
    ],
  ],
  logLevel: "info",
  bail: 0,
  waitforTimeout: 20_000,
  connectionRetryTimeout: 60_000,
  connectionRetryCount: 0,
  framework: "mocha",
  mochaOpts: {
    ui: "bdd",
    timeout: 60_000,
  },
  reporters: [
    "spec",
    [
      "junit",
      {
        outputDir: path.join(outputDirectory, "junit"),
        outputFileFormat: () => "webdriver-readiness-acl.xml",
        addFileAttribute: true,
      },
    ],
  ],
  onComplete(exitCode) {
    fs.writeFileSync(
      path.join(outputDirectory, "wdio-exit.json"),
      `${JSON.stringify({ exit_code: exitCode }, null, 2)}\n`,
      "utf8",
    );
  },
};
