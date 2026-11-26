"""Fork-side inert recipe and observation candidate. No I/O or authority.

Inputs must be supplied by the future authenticated Pandora receiving route.
This module deliberately does not implement the canonical IntegrationRequest,
AdapterInvocationResult, or REA Evidence schema. No launch or registration.
"""
from dataclasses import dataclass, field
from pathlib import PureWindowsPath, PurePosixPath
import hashlib
import json
import math
import re

CAPABILITY = 'rea.javascript.inspect'  # proposed, not registered
REVISION = 'c462a4ebd3a10e59253bcf38353a0914b176738b'
OPERATION = 'analyze_javascript_application'
MAX_PILOT_BYTES = 1024 * 1024  # research ceiling, not canonical owner policy

class Refusal(ValueError):
    """Fixed code; never exposes target path or untrusted native diagnostics."""

@dataclass(frozen=True, slots=True)
class Recipe:
    argv: tuple[str, ...] = field(repr=False)
    cwd: str = field(repr=False)
    target: str = field(repr=False)
    expected_root_digest: str  # REA-specific directory-root identity, not raw file SHA
    deadline_ms: int
    max_output_bytes: int
    max_memory_bytes: int
    fork_revision: str = REVISION
    execution_authorized: bool = field(default=False, init=False)
    native_containment_verified: bool = field(default=False, init=False)

@dataclass(frozen=True, slots=True)
class Observation:
    disposition: str
    code: str
    raw_sha256: str | None = None
    reported_evidence_id: str | None = None
    evidence_authenticated: bool = field(default=False, init=False)
    task_success_verified: bool = field(default=False, init=False)
    execution_authorized: bool = field(default=False, init=False)


def _digest(v):
    return type(v) is str and re.fullmatch(r'[a-f0-9]{64}', v) is not None


def _path(s, platform):
    if type(s) is not str or not 1 <= len(s) <= 1024 or any(ord(c)<32 or ord(c)==127 or 0xd800<=ord(c)<=0xdfff for c in s):
        raise Refusal('PATH_SHAPE_REFUSED')
    if platform == 'windows':
        # Intentionally restrict to ordinary drive-absolute paths; no UNC/device/ADS.
        if not re.match(r'^[A-Za-z]:\\',s) or '/' in s or ':' in s[2:]:
            raise Refusal('PATH_SHAPE_REFUSED')
        parts=s[3:].split('\\')
        if any(not x or x in ('.','..') or x.endswith(('.', ' ')) or re.search(r'[<>"|?*]',x) or re.fullmatch(r'(?:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[0-9¹²³]|LPT[0-9¹²³])',x.split('.')[0].rstrip(' '),re.I) for x in parts):
            raise Refusal('PATH_SHAPE_REFUSED')
        return PureWindowsPath(s)
    if platform == 'posix':
        if not s.startswith('/') or '\\' in s or any(x in ('','.','..') for x in s[1:].split('/')):
            raise Refusal('PATH_SHAPE_REFUSED')
        return PurePosixPath(s)
    raise Refusal('PLATFORM_REFUSED')


def propose(*, platform, revision, node, entry, target, workspace, expected_root_digest,
            deadline_ms, max_output_bytes, max_memory_bytes):
    """Lexical recipe only. No caller-supplied extra flags or environment forwarding."""
    if revision != REVISION or type(revision) is not str:
        raise Refusal('FORK_REVISION_REFUSED')
    n,e,t,w=(_path(x,platform) for x in (node,entry,target,workspace))
    if n.name.lower() != ('node.exe' if platform=='windows' else 'node') or e.name != 'rea.mjs' or e.parent.name != 'scripts':
        raise Refusal('ENTRY_SHAPE_REFUSED')
    # Lexical overlap checks only; native owner must handle symlinks, aliases, races.
    for a,b in ((t,w),(n,t),(e,t),(n,w),(e,w)):
        if a.is_relative_to(b) or b.is_relative_to(a):
            raise Refusal('ROOT_OVERLAP_REFUSED')
    if not _digest(expected_root_digest):
        raise Refusal('ROOT_DIGEST_REFUSED')
    for v,lo,hi in ((deadline_ms,1,120_000),(max_output_bytes,1,MAX_PILOT_BYTES),(max_memory_bytes,1,2**31)):
        if type(v) is not int or not lo <= v <= hi:
            raise Refusal('PILOT_BUDGET_REFUSED')
    return Recipe((str(n),str(e),'analyze-javascript-application',str(t),'--json'),str(w),str(t),expected_root_digest,deadline_ms,max_output_bytes,max_memory_bytes)


def _pairs(items):
    d={}
    for k,v in items:
        if k in d: raise Refusal('DUPLICATE_JSON_FIELD')
        d[k]=v
    return d


def _constant(_):
    raise Refusal('NONFINITE_JSON_REFUSED')


def _check_tree(v, depth=0):
    if depth>64: raise Refusal('JSON_DEPTH_REFUSED')
    if isinstance(v,str):
        if any(0xd800<=ord(c)<=0xdfff for c in v): raise Refusal('JSON_UNICODE_REFUSED')
    elif isinstance(v,float) and not math.isfinite(v): raise Refusal('NONFINITE_JSON_REFUSED')
    elif isinstance(v,dict):
        for k,x in v.items(): _check_tree(k,depth+1); _check_tree(x,depth+1)
    elif isinstance(v,list):
        for x in v: _check_tree(x,depth+1)


def inspect_output(recipe, raw, *, exit_code, termination, cleanup):
    """Inspect simulated supervisor facts and framing; never emit receipt/success.

    termination and cleanup are supplied observations, NOT authenticated here.
    Owner must enforce output bound while collecting, not after reading all bytes.
    """
    if type(raw) is not bytes or len(raw)>recipe.max_output_bytes:
        return Observation('hold','OUTPUT_LIMIT_REFUSED')
    digest=hashlib.sha256(raw).hexdigest()
    def stop(code): return Observation('hold',code,digest)
    if cleanup != 'complete': return stop('CLEANUP_UNRESOLVED')
    if termination != 'exited': return stop('TERMINATION_UNRESOLVED')
    if type(exit_code) is not int or exit_code!=0: return stop('PROCESS_NOT_SUCCESSFUL')
    if not raw: return stop('EMPTY_OUTPUT')
    try:
        data=json.loads(raw.decode('utf-8'),object_pairs_hook=_pairs,parse_constant=_constant)
        _check_tree(data)
    except Refusal as e: return stop(str(e))
    except (UnicodeError, ValueError, RecursionError): return stop('JSON_FRAMING_REFUSED')
    if type(data) is not dict: return stop('EVIDENCE_ENVELOPE_REFUSED')
    if 'error' in data: return stop('REA_ERROR_REPORTED')
    try:
        # This is a projection/identity screen, not a duplicate evidence schema.
        ev=data['evidence_id']; subject=data['subject']; result=data['normalized_result']; provider=data['provider']
        if type(ev) is not str or not re.fullmatch(r'ev_[a-f0-9]{64}',ev): return stop('EVIDENCE_ID_REFUSED')
        if data['operation']!=OPERATION or data['predicate_type']!='rea.javascript-application-analysis': return stop('OPERATION_MISMATCH')
        if provider['id']!='rea-javascript-application' or provider['version']!='1': return stop('PROVIDER_MISMATCH')
        if data['confidence']!='derived' or data['authority']!='shipped-artifact': return stop('EVIDENTIAL_BASIS_MISMATCH')
        if subject['format']!='directory' or result['format']!='directory': return stop('TARGET_FORMAT_MISMATCH')
        if subject['local_path']!=recipe.target or result['input_path']!=recipe.target: return stop('TARGET_PATH_MISMATCH')
        if subject['digest']['sha256']!=recipe.expected_root_digest or result['root_artifact_sha256']!=recipe.expected_root_digest: return stop('ROOT_DIGEST_MISMATCH')
        if data['parameters']['integrity_policy']!='fail' or 'source_paths' in data['parameters']: return stop('ANALYSIS_SCOPE_MISMATCH')
        if type(result['integrity_contradictions']) is not list or result['integrity_contradictions']: return stop('INTEGRITY_UNRESOLVED')
    except (KeyError,TypeError,IndexError): return stop('EVIDENCE_ENVELOPE_REFUSED')
    return Observation('hold','CANONICAL_REA_VALIDATION_REQUIRED',digest,ev)
