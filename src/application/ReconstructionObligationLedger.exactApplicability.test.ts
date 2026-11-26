import { describe, expect, it } from "vitest";
import { boundProofEvidence, exactProofEvidence, build, request, reviewedObligation } from "./ReconstructionObligationLedger.fixture.js";
import type { ReconstructionObligation, ReviewedReconstructionObligation } from "../domain/reconstructionObligationLedgerSchemas.js";
import type { ReconstructionObligationProof } from "../domain/reconstructionObligationProof.js";

type Binding = NonNullable<ReconstructionObligation["binding"]>;
type Mutation = (r: ReviewedReconstructionObligation[], b: Binding[]) => void;
type ProofMutation = (p: ReconstructionObligationProof) => void;
const ids = ["obl.applicability.a", "obl.applicability.b"];
const fixtureIds = ["fixture.applicability.a", "fixture.applicability.b"];
const verifierIds = ["verifier.applicability.a", "verifier.applicability.b"];
const claimIds = ["claim.applicability.a", "claim.applicability.b"];
const kinds = ["positive", "negative"] as const;
const noMutation = () => {};

function observe(mutate: Mutation = noMutation, changeProof: ProofMutation = noMutation, legacy = false) {
  const payload: ReconstructionObligationProof = { bindings: ids.map((id, i) => ({
    obligation_id: id, obligation_version: 1, owner_sha256: String(i + 1).repeat(64),
    fixtures: [{ fixture_id: fixtureIds[i]!, case_kind: kinds[i]!, passed: true }],
    verifiers: [{ verifier_id: verifierIds[i]!, claim_id: claimIds[i]!, passed: true }],
  })) };
  changeProof(payload);
  const proof = legacy ? boundProofEvidence("legacy", {
    obligation_ids: ids, fixture_ids: fixtureIds, case_kinds: kinds,
    verifier_ids: verifierIds, claim_ids: claimIds,
  }, "shipped-artifact") : exactProofEvidence("exact-applicability", payload, "shipped-artifact");
  const reviewed = ids.map((id, i): ReviewedReconstructionObligation => ({
    ...reviewedObligation(id, proof.evidence_id), required_case_kinds: [kinds[i]!],
  }));
  const bindings = ids.map((id, i): Binding => ({
    obligation_id: id,
    owner: { module_path: `src/${id}.ts`, symbol: "verify", owner_sha256: String(i + 1).repeat(64) },
    parser_type: null,
    original_cases: [{ kind: kinds[i]!, evidence_id: proof.evidence_id, location: `/fixture/${i}` }],
    fixtures: [{ fixture_id: fixtureIds[i]!, case_kind: kinds[i]!, authority: "unit", evidence_ids: [proof.evidence_id] }],
    verifier: { verifier_id: verifierIds[i]!, claim_id: claimIds[i]!, command: "owned inert fixture", authority: "unit", status: "pass", result_evidence_id: proof.evidence_id, enumerated_obligation_ids: [id], nondeterminism: { mode: "total-order", specification: "Fixed order." } },
  }));
  mutate(reviewed, bindings);
  const ledger = build(request([proof], { reviewed_obligations: reviewed, manifest: { bindings, contradictions: [] } }));
  return { ledger, proofId: proof.evidence_id };
}

function refused(result: ReturnType<typeof observe>, diagnostic: string) {
  expect(result.ledger.status).not.toBe("ready");
  expect(result.ledger.obligations.find(x => x.obligation_id === ids[0])?.status).not.toBe("verified");
  expect(result.ledger.obligations.find(x => x.obligation_id === ids[0])?.diagnostics.map(x => x.code)).toContain(diagnostic);
  expect(result.ledger.obligations.find(x => x.obligation_id === ids[1])?.status).toBe("verified");
}

describe("F1 exact proof applicability", () => {
  it("accepts exact matching proof for both obligations", () => {
    const result = observe();
    expect(result.ledger.status).toBe("ready");
    expect(result.ledger.obligations.map(x => x.status)).toEqual(["verified", "verified"]);
  });
  const substitutions: Array<[string, Mutation, string]> = [
    ["different implementation digest", (_, b) => { b[0]!.owner.owner_sha256 = "9".repeat(64); }, "weak-fixture-authority"],
    ["new obligation revision", (r) => { r[0]!.obligation_version = 2; }, "weak-fixture-authority"],
    ["cross-obligation fixture", (_, b) => { b[0]!.fixtures[0]!.fixture_id = fixtureIds[1]!; }, "weak-fixture-authority"],
    ["cross-obligation verifier claim", (_, b) => { b[0]!.verifier!.verifier_id = verifierIds[1]!; b[0]!.verifier!.claim_id = claimIds[1]!; }, "weak-verifier-authority"],
    ["unknown fixture", (_, b) => { b[0]!.fixtures[0]!.fixture_id = "fixture.unknown"; }, "weak-fixture-authority"],
    ["unknown verifier claim", (_, b) => { b[0]!.verifier!.claim_id = "claim.unknown"; }, "weak-verifier-authority"],
    ["explicit failed verifier", (_, b) => { b[0]!.verifier!.status = "fail"; }, "verifier-failed"],
    ["additional unproved fixture for same required case", (_, b) => { b[0]!.fixtures.push({ ...b[0]!.fixtures[0]!, fixture_id: "fixture.unproved" }); }, "weak-fixture-authority"],
  ];
  it.each(substitutions)("refuses %s", (_, mutate, code) => {
    const baseline = observe(); const changed = observe(mutate);
    expect(changed.proofId).toBe(baseline.proofId);
    refused(changed, code);
  });
  const proofChanges: Array<[string, ProofMutation, string]> = [
    ["negative fixture outcome", p => { p.bindings[0]!.fixtures[0]!.passed = false; }, "weak-fixture-authority"],
    ["negative verifier outcome", p => { p.bindings[0]!.verifiers[0]!.passed = false; }, "weak-verifier-authority"],
    ["conflicting fixture outcomes", p => { const row = p.bindings[0]!; p.bindings.push({ ...row, fixtures: [{ ...row.fixtures[0]!, passed: false }] }); }, "weak-fixture-authority"],
    ["conflicting verifier outcomes", p => { const row = p.bindings[0]!; p.bindings.push({ ...row, verifiers: [{ ...row.verifiers[0]!, passed: false }] }); }, "weak-verifier-authority"],
    ["wrong case kind", p => { p.bindings[0]!.fixtures[0]!.case_kind = "negative"; }, "weak-fixture-authority"],
  ];
  it.each(proofChanges)("refuses %s", (_, mutate, code) => refused(observe(noMutation, mutate), code));
  it("keeps legacy flat proof readable but cannot use it for closure", () => {
    const result = observe(noMutation, noMutation, true);
    expect(result.ledger.status).not.toBe("ready");
    expect(result.ledger.obligations).toHaveLength(2);
    expect(result.ledger.evidence_links).toContain(result.proofId);
    for (const item of result.ledger.obligations) {
      expect(item.status).not.toBe("verified");
      expect(item.diagnostics.map(x => x.code)).toEqual(expect.arrayContaining(["weak-fixture-authority", "weak-verifier-authority"]));
    }
  });
});
