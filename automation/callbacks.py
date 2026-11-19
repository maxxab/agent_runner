"""Pure refusal callback for a disabled runner, not an operational SDK adapter.

Nothing constructs or configures an SDK client here. A future authorized adapter
must inject this handler explicitly instead of the SDK's default acceptance.
The pinned SDK bypasses callbacks for non-string wire methods and normalizes
non-dict params to None: direct helper checks are not wire validation. Callback
errors/cancel responses never prove that processes or allocations were released.
"""


class UnsupportedServerRequest(ValueError):
    """The disabled runner has no supported response for this direct request."""


def reject_server_request(method: str, params: dict | None) -> dict:
    """Return only fixed refusals; never inspect payloads or call into a runtime."""
    if type(method) is not str or (params is not None and type(params) is not dict):
        raise UnsupportedServerRequest('Unsupported server request while runner execution is disabled.')
    if method in ('item/commandExecution/requestApproval', 'item/fileChange/requestApproval'):
        return {'decision': 'cancel'}
    if method == 'item/tool/call':
        return {'success': False, 'contentItems': [
            {'type': 'inputText', 'text': 'Runner execution is disabled.'}]}
    raise UnsupportedServerRequest('Unsupported server request while runner execution is disabled.')
