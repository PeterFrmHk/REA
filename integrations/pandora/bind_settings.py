"""REA fork-side proposal compiler for one offline owned-fixture pilot.

Uses canonical Pandora owner models. Never authorizes or executes a command.
The separate expected settings are review inputs, not trusted by their type.
No owner contract is reproduced; scope conventions below are pilot-specific.
"""
from dataclasses import dataclass, field
import hashlib
import json
from pydantic import ValidationError
from pandora.integrations.contracts import AdapterClass, IntegrationRequest
from pandora.contracts.execution_isolation_v1 import IsolationRequest, TrustClass
from .recipe import CAPABILITY, REVISION, Recipe, Refusal, propose, _digest

PILOT_EFFECTS = frozenset({'shell_subprocess', 'workspace_write'})

@dataclass(frozen=True, slots=True)
class PilotBinding:
    recipe: Recipe = field(repr=False)
    isolation: IsolationRequest = field(repr=False)
    request_sha256: str
    disposition: str = field(default='HOLD_OWNER_ADMISSION', init=False)
    execution_authorized: bool = field(default=False, init=False)


def bind_settings(request, isolation, *, platform, node, entry,
                  expected_repository_ref, expected_code_sha256,
                  expected_profile_sha256, expected_input_ref,
                  expected_input_sha256, expected_root_digest):
    """Revalidate then translate one scoped proposal; no IO or dispatch.

    expected_* must ultimately come from the respective owners' custody.
    Matching values alone establish correspondence, not authenticity.
    Input snapshot SHA and REA directory root digest are separate domains.
    """
    try:
        if type(request) is not IntegrationRequest or type(isolation) is not IsolationRequest:
            raise Refusal('OWNER_MODEL_REQUIRED')
        req = IntegrationRequest.model_validate(request.model_dump(mode='python'))
        iso = IsolationRequest.model_validate(isolation.model_dump(mode='python'))
    except (ValidationError, TypeError, ValueError) as exc:
        if isinstance(exc, Refusal): raise
        raise Refusal('OWNER_CONTRACT_REFUSED') from None
    if (req.adapter_class != AdapterClass.TOOL or req.capability != CAPABILITY
            or req.action_type != CAPABILITY or req.side_effect_class != 'write_sandbox'
            or req.authority_zone != 'fixtures' or set(req.authorized_effects) != PILOT_EFFECTS):
        raise Refusal('PILOT_ROUTE_REFUSED')
    if not all((req.task_ref, req.order_id, req.authority_ref)):
        raise Refusal('UPSTREAM_REFERENCES_REQUIRED')
    # Explicit pilot correlation, not a general assertion about owner ID formats.
    if req.request_id != iso.request_id or req.order_id != iso.order_ref:
        raise Refusal('REQUEST_BINDING_MISMATCH')
    if iso.trust_class != TrustClass.TRUSTED_LOCAL or not iso.admission_ref:
        raise Refusal('PILOT_TRUST_SCOPE_REFUSED')
    if (type(expected_repository_ref) is not str or not expected_repository_ref
            or iso.repository_ref != expected_repository_ref or iso.head_sha != REVISION
            or not _digest(expected_code_sha256) or iso.code_sha256 != expected_code_sha256
            or not _digest(expected_profile_sha256) or iso.profile_sha256 != expected_profile_sha256):
        raise Refusal('ENGINE_PROFILE_IDENTITY_MISMATCH')
    if not _digest(expected_input_sha256) or not _digest(expected_root_digest):
        raise Refusal('EXPECTED_INPUT_IDENTITY_REQUIRED')
    # No paths, arguments, settings or effect authority from adapter payload.
    p = req.adapter_payload
    if (set(p) != {'target_ref'} or type(p['target_ref']) is not str
            or type(expected_input_ref) is not str or not expected_input_ref
            or p['target_ref'] != expected_input_ref):
        raise Refusal('TARGET_REFERENCE_MISMATCH')
    g = iso.grants
    if (len(g.inputs) != 1 or g.outputs or g.network_mode != 'none'
            or g.network_destinations or g.secret_names or g.device_refs or g.capabilities
            or g.inherit_environment or g.environment_names or g.privileged or g.host_namespaces
            or not g.read_only_root or not g.no_new_privileges or not g.scratch_disposable
            or g.security_profile_ref is None or g.working_directory != g.scratch_directory):
        raise Refusal('PILOT_GRANTS_REFUSED')
    inp = g.inputs[0]
    if inp.source_ref != expected_input_ref or inp.sha256 != expected_input_sha256:
        raise Refusal('SNAPSHOT_BINDING_MISMATCH')
    # The owner retains all other limits verbatim. Do not confuse REA inner heap
    # or per-source timeout with whole-process-tree budget enforcement.
    recipe = propose(platform=platform, revision=iso.head_sha, node=node, entry=entry,
        target=inp.target, workspace=g.working_directory,
        expected_root_digest=expected_root_digest, deadline_ms=g.limits.wall_time_ms,
        max_output_bytes=g.limits.stdout_bytes, max_memory_bytes=g.limits.memory_bytes)
    # Snapshot only the declared request for reproducible identity; not a signature.
    digest = hashlib.sha256(json.dumps(req.model_dump(mode='json'), sort_keys=True,
        separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()).hexdigest()
    return PilotBinding(recipe, iso, digest)


def reconcile_capture(binding, evidence, raw, *, expected_execution_id):
    """Correlate a *reported* capture to the proposal and actual owner model.

    No owner authenticity, process control, evidence custody or semantic success
    is inferred. Preserve the caller's original evidence independently.
    """
    from pandora.contracts.execution_isolation_v1 import IsolationEvidence
    from .recipe import Observation, inspect_output
    if type(binding) is not PilotBinding:
        raise Refusal('PILOT_BINDING_REQUIRED')
    if type(evidence) is not IsolationEvidence:
        return Observation('hold', 'OWNER_ISOLATION_EVIDENCE_REQUIRED')
    try:
        observed = IsolationEvidence.model_validate(evidence.model_dump(mode='python'))
    except (ValidationError, TypeError, ValueError):
        return Observation('hold', 'OWNER_ISOLATION_EVIDENCE_REFUSED')
    if (type(expected_execution_id) is not str or not expected_execution_id
            or observed.execution_id != expected_execution_id
            or observed.decision.request != binding.isolation):
        return Observation('hold', 'CAPTURE_BINDING_MISMATCH')
    if (observed.status != 'succeeded' or not observed.execution_started
            or observed.pre_start_verification != 'passed'
            or observed.teardown != 'verified' or observed.restoration == 'failed'):
        return Observation('hold', 'OWNER_EXECUTION_UNRESOLVED')
    return inspect_output(binding.recipe, raw, exit_code=observed.exit_code,
                          termination='exited', cleanup='complete')
