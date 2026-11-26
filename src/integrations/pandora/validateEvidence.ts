/** Fork-owned semantic validation and external identity correspondence.
 * Expected values must originate in admitted custody, not in REA's output.
 * No execution, authority, capture authentication or complete-coverage claim.
 */
import { parseEvidence } from "../../domain/evidence.js";
import { javascriptApplicationAnalysisResultSchema } from "../../domain/javascript/javascriptApplicationAnalysis.js";

export const validatePandoraStaticEvidence = (
  input: unknown,
  expected: Readonly<{ target: string; rootDigest: string }>,
) => {
  if (typeof expected.target !== "string" || expected.target.length === 0 ||
      typeof expected.rootDigest !== "string" || !/^[a-f0-9]{64}$/u.test(expected.rootDigest)) {
    throw new TypeError("PANDORA_REA_EXPECTED_IDENTITY_REQUIRED");
  }
  const evidence = parseEvidence(input);
  if (evidence.operation !== "analyze_javascript_application" ||
      evidence.predicate_type !== "rea.javascript-application-analysis" ||
      evidence.provider.id !== "rea-javascript-application" || evidence.provider.version !== "1" ||
      evidence.confidence !== "derived" || evidence.authority !== "shipped-artifact") {
    throw new TypeError("PANDORA_REA_OPERATION_OR_BASIS_MISMATCH");
  }
  const result = javascriptApplicationAnalysisResultSchema.parse(evidence.normalized_result);
  if (evidence.subject?.format !== "directory" || result.format !== "directory" ||
      evidence.subject.local_path !== expected.target || result.input_path !== expected.target ||
      evidence.subject.digest.sha256 !== expected.rootDigest || result.root_artifact_sha256 !== expected.rootDigest) {
    throw new TypeError("PANDORA_REA_TARGET_IDENTITY_MISMATCH");
  }
  // Match the fixed R4 command, not an arbitrary source-selection request.
  if (evidence.parameters.integrity_policy !== "fail" || evidence.parameters.source_paths !== undefined ||
      result.integrity_contradictions.length !== 0) {
    throw new TypeError("PANDORA_REA_SCOPE_OR_INTEGRITY_MISMATCH");
  }
  return { evidence, result };
};
