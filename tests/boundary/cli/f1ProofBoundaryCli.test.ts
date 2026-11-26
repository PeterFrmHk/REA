import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { cases } from "../../fixtures/f1ProofBoundary.fixture.js";
const execute = promisify(execFile);
describe("F1 compiled CLI proof applicability", () => {
  it.each(cases)("%s", async (_, ready, make) => {
    const {input, ledger} = make();
    expect(ledger.status === "ready").toBe(ready);
    const arg = JSON.stringify(input);
    expect(arg.length).toBeLessThan(16000);
    const {stdout} = await execute(process.execPath, ["scripts/rea.mjs", "build-reconstruction-obligation-ledger", arg, "--json"], {
      cwd: process.cwd(), env: {
        SystemRoot: process.env.SystemRoot, TEMP: process.env.TEMP,
        TMP: process.env.TMP, REA_LOG_LEVEL:"silent",
      }, maxBuffer: 1024*1024, timeout: 20000,
    });
    const evidence = parseEvidence(JSON.parse(stdout));
    expect(evidence.operation).toBe("build_reconstruction_obligation_ledger");
    expect(evidence.normalized_result).toEqual(ledger);
  }, 30000);
});
