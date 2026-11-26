import { boundProofEvidence, exactProofEvidence, build, request, reviewedObligation } from "../../src/application/ReconstructionObligationLedger.fixture.js";
import type { ReconstructionObligation, ReviewedReconstructionObligation } from "../../src/domain/reconstructionObligationLedgerSchemas.js";
import type { ReconstructionObligationProof } from "../../src/domain/reconstructionObligationProof.js";

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
  const input = request([proof], { reviewed_obligations: reviewed, manifest: { bindings, contradictions: [] } });
  return { input, ledger: build(input), proofId: proof.evidence_id };
}

export const cases: Array<[string, boolean, () => ReturnType<typeof observe>]> = [
  ["exact", true, () => observe()],
  ["owner mismatch", false, () => observe((_, b) => { b[0]!.owner.owner_sha256 = "9".repeat(64); })],
  ["revision mismatch", false, () => observe(r => { r[0]!.obligation_version = 2; })],
  ["foreign fixture", false, () => observe((_, b) => { b[0]!.fixtures[0]!.fixture_id = fixtureIds[1]!; })],
  ["foreign verifier", false, () => observe((_, b) => { b[0]!.verifier!.verifier_id = verifierIds[1]!; b[0]!.verifier!.claim_id = claimIds[1]!; })],
  ["legacy", false, () => observe(noMutation, noMutation, true)],
  ["conflicting outcomes", false, () => observe(noMutation, p => { const r = p.bindings[0]!; p.bindings.push({...r, fixtures:[{...r.fixtures[0]!, passed:false}]}); })],
  ["extra unproved fixture", false, () => observe((_, b) => { b[0]!.fixtures.push({...b[0]!.fixtures[0]!,fixture_id:"fixture.unproved"}); })],
];
