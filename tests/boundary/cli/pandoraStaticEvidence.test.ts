/** Native review candidate: run only in an admitted scratch REA checkout.
 * Uses the existing CLI harness and service; no provider or application execution.
 * REA's static analysis itself can launch a worker. No Pandora authority claim.
 */
import { realpath, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect } from "vitest";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { validatePandoraStaticEvidence } from "../../../src/integrations/pandora/validateEvidence.js";
import { analyzeJavaScriptApplication } from "../../support/javascriptApplicationScope.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { cliTest } from "../../support/cli/cliFixture.js";

const files = {
  "index.js": "import { total } from \"./total.js\";\nexport const example = total([1, 2, 3]);\n",
  "package.json": "{\"name\":\"rea-pandora-static-fixture\",\"version\":\"0.0.1\",\"private\":true,\"type\":\"module\"}\n",
  "total.js": "export function total(values) { return values.reduce((a, b) => a + b, 0); }\n"
} as const;
const expectedRoot = "12d971246fd41507be2d5a393d0153649d2165bd1beffcf1d97d3bd57b10ec2a";

cliTest("Pandora owned flat fixture: service, CLI and canonical validator agree", async ({ cli }) => {
  const root = await realpath(await createTestTempDirectory("rea-pandora-static-"));
  for (const [name, content] of Object.entries(files)) {
    await writeFile(join(root, name), content, "utf8");
  }
  const direct = await analyzeJavaScriptApplication({ input_path: root });
  if (!direct.ok) throw direct.error;
  const expected = { target: root, rootDigest: expectedRoot };
  const directValidated = validatePandoraStaticEvidence(direct.value, expected);
  const output = await cli.run({
    arguments: ["analyze-javascript-application", root, "--json"],
    environment: { REA_LOG_LEVEL: "silent" },
  });
  expect(output.exitCode).toBe(0);
  // Post-collection observation only: the EXE supervisor must enforce its stream bound while collecting.
  expect(Buffer.byteLength(output.stdout, "utf8")).toBeLessThanOrEqual(1024 * 1024);
  const fromCli = validatePandoraStaticEvidence(output.json, expected);
  expect(fromCli.evidence).toEqual(directValidated.evidence);
  expect(fromCli.evidence.subject?.digest.sha256).toBe(expectedRoot);
  expect(fromCli.result.root_artifact_sha256).toBe(expectedRoot);
  expect(fromCli.evidence.subject?.local_path).toBe(root);
  expect(fromCli.result.input_path).toBe(root);
  expect(fromCli.evidence.confidence).toBe("derived");
  expect(fromCli.evidence.authority).toBe("shipped-artifact");
  // Modify semantic content without recomputing the content-addressed ID.
  expect(() => validatePandoraStaticEvidence({
    ...fromCli.evidence, normalized_result: { ...fromCli.result, root_artifact_sha256: "0".repeat(64) },
  }, expected)).toThrow();
  expect(() => validatePandoraStaticEvidence({
    ...fromCli.evidence, evidence_id: "ev_" + "0".repeat(64),
  }, expected)).toThrow();
  // Subject display path is excluded from the canonical Evidence ID projection.
  // The owner parser can accept it, but external target correspondence must refuse.
  const moved = { ...fromCli.evidence, subject: { ...fromCli.evidence.subject!, local_path: root + "-other" } };
  expect(parseEvidence(moved).evidence_id).toBe(fromCli.evidence.evidence_id);
  expect(() => validatePandoraStaticEvidence(moved, expected)).toThrow("PANDORA_REA_TARGET_IDENTITY_MISMATCH");
  expect(() => validatePandoraStaticEvidence(fromCli.evidence, { ...expected, rootDigest: "0".repeat(64) })).toThrow("PANDORA_REA_TARGET_IDENTITY_MISMATCH");
});
