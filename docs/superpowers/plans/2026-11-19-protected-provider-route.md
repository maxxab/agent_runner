# RNR-D00 protected provider route — design to challenge

Status: proposal, not accepted source or authority to use credentials/model.
Current runtime fixture cannot satisfy operational release. This design retains
Codex inside the guardian-managed application allocation and project commands in
their separately admitted workload allocations. Existing NetworkMode=none stays.
No public model API key is substituted for the user's established ChatGPT sign-in.
Main owns this interface; independent review must challenge it before implementation.

## Proposed simplest route

Extend the existing native guardian's bounded framing loop with one fixed
loopback-only HTTP listener in the private application network namespace. Its
only client is the original qualified Codex app-server process. It forwards finite
provider frames over the existing guardian-host transport to a host-side broker
owned by the trusted Main, outside app/project access. Main performs upstream TLS
with the existing ChatGPT account identity. No credential or host network capability
is mounted/inherited by Codex or any project workload. No new relay subprocess,
provider-mode selector, direct container egress or separate Store is introduced.
This modifies the SINGLE actual runtime profile, including guardian/Codex TCP
listener/connection FDs and typed stream frames; whole-profile qualification remains
mandatory. The old fixture remains historical unit input, never a selectable real
route or operational fallback.

Alternatives considered: a separately contained relay adds another process/lifetime/
FD/control closure and is unnecessary if the existing guardian loop can mediate;
hosting Codex outside the runtime allocation changes accepted containment and
startup assumptions; putting upstream credentials into Codex violates the protected
credential boundary. Tokenless endpoint possession is not admission. The proposed
route is only preferred if independent review finds its finite protocol and
identity/bypass evidence implementable. No choice here is called user-approved.

## Client authentication and finite admission to freeze

Use the installation-time immutable gateway capability proposed below; it
supersedes the earlier per-attempt capability delivery proposal. Rotate only
through reviewed installation, before sealing the app configuration. The
capability alone grants nothing: exact original guardian/channel/instance and
closed process/socket membership plus fresh sole-Store permits remain mandatory.
Never infer client authentication from loopback or IP address. No secret is
printed, committed or shared across project installations.

Each upstream effect needs durable pre-reservation by the EXISTING Store owner,
with immutable project/installation/attempt/session/turn/request/body binding.
One logical app-server turn may generate multiple model HTTP requests, tool
continuations and retries. Exact bounds must come from the pinned client and be
recorded as finite subrequests under the admitted logical turn; no equivalence
of HTTP request with logical turn, alternate catalog fetch, hidden retry,
reconnection, 401 replay or gateway reauthorization is assumed safe. The first
profile should reject concurrent outstanding requests and disable client retries
where supported, with broker enforcement even if client retries. A request body
not matching the frozen model/tool/configuration/capability rules rejects before
network. Actual JSON/body/SSE/header/chunk/time/output maxima, supported paths
and final completion semantics must be frozen against the actual client.

Once a send can have occurred, unknown/lost response remains charged and UNKNOWN;
no retry/resend. Cancellation/expiry fences admission immediately, closes owned
I/O and lets independent negative containment enforce original deadlines. Main
provider workers cannot extend15/44/60/90, block keeper or mutate Store from an
unserialized reader path. DNS/TLS and network stalls need their own bounded
worker/lifetime model; a Python socket timeout alone is not a whole guarantee.

## Existing sign-in custody to challenge

Official [gateway guidance](https://learn.chatgpt.com/docs/enterprise/connect-to-a-gateway)
allows a gateway to authenticate upstream itself. It does not implement this
project's broker, grant account access or establish old CLI compatibility.
Official [account-auth guidance](https://learn.chatgpt.com/docs/auth/ci-cd-auth)
uses Codex itself for refresh and keeps its updated private auth cache serialized;
a custom refresh-token implementation is not proposed.

Possible bounded first-release custody: a reviewed, fixed, owner-established
private account profile remains outside all app/project views. The trusted broker
reads a bounded auth record containing access, refresh and identity material,
extracts only the needed current access credential/account fields in memory,
and discards unused fields. Nofollow/ownership/private-mode/regular-file and
before/after identity checks do not serialize a concurrent refresh writer;
exclusive profile custody must be established separately. Never log record
contents, headers or tokens or save them in evidence. It neither writes the profile nor calls
refresh endpoints. Expired/missing/changed credentials or401 fence without retry;
owner's ordinary Codex-managed sign-in/refresh remains the supported maintenance
route. No profile is inspected or copied during design. The exact supported token
format/current endpoint/account header and profile ownership must be verified from
pinned source before this is an implementation contract. A helper route should
replace direct cache parsing if the selected client supplies a supported bounded
credential interface; no undocumented helper or token export is invented.

This custody is not yet accepted. It must not silently share enrollment/store/
identity between projects, race/rotate another active profile, disclose upstream
credentials to Codex/project code, or turn public project code into a trusted
credential holder. Account permission and model availability are unverified.

## Current evidence and independent acceptance needed

Installed host CLI reports0.162.1. Historical SDK/package metadata identifies the
separately pinned runtime candidate as0.167.0; its observed SHA256
cdcb45aaa01d0f14e298985e09465aebccd47f64ecd298aea44814af7b62bbda
matches both SDK inventory and native HTTP candidate pin. The pinned runtime
was not executed. Version compatibility must target the selected runtime binary,
not infer its behavior from host CLI help. runtime-candidate-version.json records
this verified distinction; it does not qualify the binary/profile or select a
new runtime. Offline HOST schema generation succeeded with317
app-server schemas but contains no provider-internal type/schema; it proves no
HTTP/retry/auth compatibility. The initial anticipated source paths failed;
the exact pinned source was subsequently recovered as recorded below. Existing0.167 experiment bytes must not
be substituted silently. Protected provider-research.json records binary hash
and fetched official sources; no account cache/settings were read or changed.

Before source: reviewer challenges guardian relay versus separate broker topology,
nonce delivery/immutable closure, sole-Store request inventory, all concurrency and
blocking paths, credential custody and exact client compatibility. Before actual
model work: complete original supervised launch/observer/Store/profile/closure
gates and explicitly scoped finite candidate qualification. Need observed denied
project->broker/provider and app->alternate-provider routes, expired/foreign/
replayed/exhausted permits, partial/lost sends, internal retries, cancellation,
broker/guardian/app death and original deadline retention. Successful text alone
is not proof of a real admitted callback or route. No release gate closes here.

## Recovered pinned source and revised candidates (still for challenge)

The initial failures were stale module paths. Official tag rust-v0.167.0 resolves
to source commit cb41599ccbe371272892f156286a236aa097bada; relevant files were
fetched via GitHub and saved under protected upstream-01670 with resource URIs
and SHA256 in retrieval-index.json. Version labels alone still do not prove
source-to-binary correspondence or qualify the observed candidate. No source was
imported into the runtime package, and no credential read occurred.

- [Provider definitions](https://github.com/openai/codex/blob/cb41599ccbe371272892f156286a236aa097bada/codex-rs/model-provider-info/src/lib.rs)
  define request_max_retries/stream_max_retries and supports_websockets.
  codex-client retry.rs iterates0..=max_attempts, so request_max_retries0
  requests one transport attempt. This does not close higher-level retry paths.
- [Responses metadata](https://github.com/openai/codex/blob/cb41599ccbe371272892f156286a236aa097bada/codex-rs/core/src/responses_metadata.rs)
  includes session_id/thread_id/turn_id in client_metadata and emits bounded
  x-codex-turn-metadata compatibility JSON. core/client.rs constructs these from
  internal turn context and adds them to Responses HTTP requests; endpoint
  responses.rs also sends session-id/thread-id. These are request values, not
  standalone authority. Actual broker correlation must match the original
  app-server-issued thread/turn ACK observed on its authenticated control stream.
- [Higher-level retry](https://github.com/openai/codex/blob/cb41599ccbe371272892f156286a236aa097bada/codex-rs/core/src/responses_retry.rs)
  has UnboundedConnectionRetries before the ordinary max-retries branch, plus
  transport fallback. A real profile must explicitly exclude that feature and
  WebSockets/fallback, then prove effective settings and physical denial. The
  present fixture FEATURES/observation does not establish that exclusion.
- login/src/auth/storage.rs and token_data.rs define AuthDotJson.tokens and
  TokenData.access_token/account_id. This establishes source schema, not current
  credential validity, acceptable account ownership, or permission to race a
  mutable host profile. The built-in responses-api-proxy supports API-key and
  federated identity paths; it is not a ready ChatGPT-account broker for this
  first-release contract. No custom refresh is proposed.

P1 refinement candidate: provision the gateway-only capability once in the
project-specific protected installation, before sealing actual config/asset roots.
Keep it immutable for that installation; do not introduce a fresh per-attempt
config rewrite. Attempt authentication still binds original guardian/channel/
namespace/instance and sole-Store permits; an old capability cannot grant another
attempt. Replacement requires a newly reviewed installation/closure, never a
runtime override. No upstream credential is included. This removes the proposed
after-seal mutation, but exact authenticated client membership must still be proven.

P2 refinement candidate: hold at most one bounded initial HTTP request without
upstream effects until the original app-server turn/start ACK/turn/started event
is independently bound by the sole Store. Compare source-generated session/thread/
turn metadata to that binding. For the first fixed real qualification, permit
only one initial sampling request and one continuation after the exact model-issued
rnr_command callback has been admitted, executed and its result sent through the
protected control stream. The continuation must retain the original request
history plus the exact observed function call/result; a retry/duplicate body,
unsolicited/background/compaction request, second command or unknown history has
no permit. Cap alone is insufficient: exact body/history/tool/response correlation
and durable request records must be frozen against actual serialization. This
candidate does not reduce wider accepted product requirements or claim that one
qualification turn implements the whole scheduler/runner release.

P3/P4, nonce/client identity, TLS-worker containment, actual source/binary/profile
correspondence and final qualified account source remain open. No provider source
implementation or model request is released from these research findings.

## Reviewed finite configuration prerequisite

Main traced build_qualification through the ordinary/requirements TOML, manifest
publication and managed_observation's exact effective-provider/features comparison.
The old profile left request/stream retries unset and did not disable the stable,
default-true unbounded_connection_retries feature. Pinned features/src/lib.rs
confirms the feature name/default; protected exact source blob
8a9a0975edee02d4fa4e2aeee0d69b2d849e7a97 is retained alongside the source index.
Both generated files now explicitly set request_max_retries=0,
stream_max_retries=0, supports_websockets=false and disable that feature.
Observation rejects missing/null/increased retry limits, boolean false substituted
for numeric zero, and enabled retry feature. This changes only inert fixture
inputs and their startup checks; no real provider endpoint or credential is added.

Regression first failed on the absent unbounded retry control; all19 focused tests
then passed. Reviewer v4 independently accepted the three-file snapshot and
passed19 checks (0.262s); evidence is reviewer-v4-native/managed-retry-qa.log.
This does not prove actual client behavior or close the separate unauthorized
recovery loop. The complete profile still needs actual finite qualification.

Reviewer v4's source challenge requires pending requests to remain wholly bounded
by the original deadline, with no upstream byte before durable sole-Store identity
acceptance. Thread/turn expectations come only from the authenticated control
stream; session identity must account for responses_session_id overrides/cache
affinity. Freeze complete initial body and exact continuation serialization,
including reasoning/output IDs, rather than matching turn IDs alone. Consumed
phase rejects every duplicate or changed-body retry. Account source, issuer and
route must be explicit; reject unsupported residency/FedRAMP routes. HTTP/SSE/
framing/backpressure, authenticated closed process/socket membership, finite
host-worker lifetime and source-to-binary/profile proof remain open.

### Conditional unauthorized-recovery source result

Reviewer v4 followed the pinned provider/auth manager code and found that an
actually credential-free process with no external/runtime/gateway auth does not
reload, refresh or resend after401: UnauthorizedRecovery.has_next returns false
when cached auth is None. requires_openai_auth=false by itself does not establish
this; the configured provider retains its manager. Manager startup can read
configured/ephemeral/environment credential sources. A static http_headers gateway
capability does not create external CodexAuth::Headers. Exact sources/provenance
and trace: protected reviewer-v4-native/unauthorized-source/report.md.

The actual guardian currently execs Codex with only HOME, CODEX_HOME and LANG;
the transport admits a closed bootstrap/turn/tool method set. These source facts
are relevant controls, not physical auth-absence proof. Actual home/image/storage,
startup cache state and absence of later login/token injection must be qualified.
The broker separately consumes the upstream permit before I/O and fences on401;
no client branch can manufacture a replacement permit. All real provider gates
remain open and no credentials were inspected for this source conclusion.
