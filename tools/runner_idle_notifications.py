"""Pure validation for the credential-free, idle initialization diagnostic.

A disabled status is a protocol observation, not proof of startup policy,
remote-control prevention, lifecycle acceptance or permission to run work.
The caller must still bound and strictly decode each JSON frame.
"""


def validate_idle_notification(value):
    def reject():
        raise ValueError('unexpected idle notification') from None

    if (type(value) is not dict or
            set(value) - {'method', 'params', 'jsonrpc', 'emittedAtMs'} or
            value.get('jsonrpc', '2.0') != '2.0' or
            type(value.get('params')) is not dict):
        reject()
    if 'emittedAtMs' in value:
        timestamp = value['emittedAtMs']
        if type(timestamp) is not int or not -(2**63) <= timestamp < 2**63:
            reject()
    method = value.get('method')
    if method == 'configWarning':
        return
    if method != 'remoteControl/status/changed':
        reject()
    params = value['params']
    required = {'status', 'installationId', 'serverName'}
    if (not required <= set(params) or set(params) - (required | {'environmentId'}) or
            params['status'] != 'disabled' or
            type(params['installationId']) is not str or type(params['serverName']) is not str or
            (params.get('environmentId') is not None and type(params['environmentId']) is not str)):
        reject()
