"""Frozen Annex A synthetic bootstrap profile; no process or network access.

Schema citations refer to the SHA256-pinned B artifacts in the accepted RNR-D00
contract. Validation uses only source constants, never ambient schema/config files.
Matching a synthetic recipe is consistency evidence, not peer authentication.
"""
from dataclasses import dataclass
import json
from .control_store import BootstrapSpec, validate_record, record_digest
from .control_transport import decode, turn_id, bounded_text, _identifier

MAX_FRAME = 1_048_576


def closed(value, required, optional=()):
    if type(value) is not dict or not set(required) <= value.keys() or value.keys() - set(required) - set(optional):
        raise ValueError('closed pinned object required')


def int64(value, *, nonnegative=False):
    if type(value) is not int or not (0 if nonnegative else -(2**63)) <= value < 2**63:
        raise ValueError('bounded int64 required')


def bounded_json(value, byte_limit=MAX_FRAME):
    """Bound all objects, including upstream open config JSON, before retaining."""
    pending = [(value, 0)]; nodes = text_bytes = 0
    while pending:
        item, depth = pending.pop(); nodes += 1
        if nodes > 4096 or depth > 16:
            raise ValueError('JSON structure bound exceeded')
        if type(item) is dict:
            for key, child in item.items():
                if type(key) is not str: raise ValueError('JSON key required')
                text_bytes += len(key.encode('utf-8'))
                pending.append((child, depth + 1))
        elif type(item) is list:
            pending.extend((child, depth + 1) for child in item)
        elif type(item) is str:
            text_bytes += len(item.encode('utf-8'))
        elif item is not None and type(item) not in (bool, int, float):
            raise ValueError('JSON value required')
        if text_bytes > byte_limit:
            raise ValueError('JSON text bound exceeded')
    return text_bytes


def _spec(spec):
    if type(spec) is not BootstrapSpec: raise ValueError('protected BootstrapSpec required')
    validate_record(spec)
    if spec.approvals_reviewer != 'user': raise ValueError('pinned approvals reviewer required')


def validate_thread(thread, spec):
    """B/v2/ThreadStartResponse.json#/definitions/Thread, narrowed by Annex A."""
    required = {'cliVersion','createdAt','cwd','ephemeral','id','modelProvider','preview',
                'projectId','sessionId','source','status','turns','updatedAt','environments'}
    nulls = {'forkedFromId','parentThreadId','agentNickname','agentRole','gitInfo','path',
             'name','originator','extra','section','sectionEnteredAt','threadSource','daybreakEnabled'}
    optional = nulls | {'historyMode','canAcceptDirectInput','model','reasoningEffort','recencyAt'}
    closed(thread, required, optional)
    turn_id(thread['id']); turn_id(thread['sessionId'])
    for k in ('createdAt','updatedAt'): int64(thread[k])
    if thread.get('recencyAt') is not None: int64(thread['recencyAt'])
    expected = {'cliVersion':spec.cli_version,'cwd':spec.runtime_cwd,'modelProvider':spec.provider,
                'ephemeral':True,'source':'appServer','environments':[],'turns':[],
                'preview':'','projectId':None,'status':{'type':'idle'}}
    if any(type(thread[k]) is not type(v) or thread[k] != v for k,v in expected.items()):
        raise ValueError('fresh isolated thread profile mismatch')
    if any(thread.get(k) is not None for k in nulls): raise ValueError('unselected thread provenance')
    for k,v in [('historyMode','legacy'),('canAcceptDirectInput',True),('model',spec.model),('reasoningEffort',spec.effort)]:
        if k in thread and (type(thread[k]) is not type(v) or thread[k] != v):
            raise ValueError('thread policy mismatch')
    return thread


def _layer_source(value):
    # ConfigReadResponse#/definitions/ConfigLayerSource.
    variants = {'packagedDefaults':('file',), 'mdm':('domain','key'), 'system':('file',),
                'enterpriseManaged':('id','name'), 'user':('file',), 'project':('dotCodexFolder',),
                'sessionFlags':(), 'legacyManagedConfigTomlFromFile':('file',),
                'legacyManagedConfigTomlFromMdm':()}
    if type(value) is not dict or type(value.get('type')) is not str or value['type'] not in variants:
        raise ValueError('pinned config source required')
    closed(value, {'type',*variants[value['type']]}, {'profile'} if value['type']=='user' else ())
    for k,v in value.items():
        if k == 'profile' and v is None: continue
        bounded_text(v, MAX_FRAME)
        if k in ('file','dotCodexFolder'):
            from .control_store import normalized_path
            normalized_path(v)


def _config(result, spec):
    # B/v2/ConfigReadResponse.json. Config/layer.config are the manifest-bound
    # open JSON regions; other structural objects are closed to pinned fields.
    closed(result, {'config','origins','layers'})
    if type(result['config']) is not dict or type(result['origins']) is not dict or type(result['layers']) is not list:
        raise ValueError('complete config/layers required')
    _schema(result['config'], _CONFIG_DEFINITIONS['Config'])
    for value in result['origins'].values():
        closed(value, {'name','version'}); _layer_source(value['name']); bounded_text(value['version'], MAX_FRAME)
    for layer in result['layers']:
        closed(layer, {'name','version','config'}, {'disabledReason'})
        _layer_source(layer['name']); bounded_text(layer['version'], MAX_FRAME)
        if layer.get('disabledReason') is not None: bounded_text(layer['disabledReason'],MAX_FRAME)
    if (record_digest(result['config']) != spec.expected_config_digest or
            record_digest({'layers':result['layers'],'origins':result['origins']}) != spec.expected_layers_digest):
        raise ValueError('protected full config manifest mismatch')


def validate_bootstrap_response(step, raw: bytes, spec: BootstrapSpec) -> dict:
    """Strict complete response validation; Store repeats it independently."""
    _spec(spec)
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_FRAME: raise ValueError('bounded bytes required')
    try:
        message = decode(raw); bounded_json(message)
    except (UnicodeError, RecursionError) as error:
        raise ValueError('invalid bounded UTF-8 JSON') from error
    closed(message, {'id','result'})
    if not _identifier(message['id']): raise ValueError('wire identity required')
    result = message['result']
    if step == 'initialize':
        expected = dict(codexHome=spec.runtime_home,platformFamily=spec.platform_family,
                        platformOs=spec.platform_os,userAgent=spec.user_agent)
        closed(result, expected)
        if result != expected: raise ValueError('initialize fingerprint mismatch')
    elif step == 'config_read':
        _config(result,spec)
    elif step == 'thread_start':
        expected = dict(model=spec.model,modelProvider=spec.provider,cwd=spec.runtime_cwd,
                        approvalPolicy='never',approvalsReviewer='user',sandbox={'type':'dangerFullAccess'},
                        reasoningEffort=spec.effort,runtimeWorkspaceRoots=[],instructionSources=[],disabledPluginIds=[])
        closed(result, {'thread',*expected}, {'multiAgentMode','serviceTier','activePermissionProfile'})
        if any(type(result[k]) is not type(v) or result[k] != v for k,v in expected.items()):
            raise ValueError('thread start policy mismatch')
        if (result.get('multiAgentMode','explicitRequestOnly') != 'explicitRequestOnly' or
                result.get('serviceTier') is not None or result.get('activePermissionProfile') is not None):
            raise ValueError('unselected thread start policy')
        validate_thread(result['thread'],spec)
    else:
        raise ValueError('unknown bootstrap step')
    return message


def build_bootstrap_request(step, wire_id, spec, bounds):
    """B InitializeParams/ConfigReadParams/ThreadStartParams exact fixed recipe."""
    _spec(spec)
    if not _identifier(wire_id): raise ValueError('wire identity required')
    if step == 'initialize':
        method='initialize'
        params={'clientInfo':{'name':'rnr-source','version':'3'},'capabilities':{
            'experimentalApi':True,'explicitGatewayOauth':True,'mcpServerOpenaiFormElicitation':False,
            'requestAttestation':False,'extensions':None,'optOutNotificationMethods':[]}}
    elif step == 'config_read':
        method='config/read'; params={'cwd':spec.runtime_cwd,'includeLayers':True}
    elif step == 'thread_start':
        method='thread/start'; params=dict(model=spec.model,modelProvider=spec.provider,cwd=spec.runtime_cwd,
            approvalPolicy='never',sandbox='danger-full-access',ephemeral=True,environments=[],
            runtimeWorkspaceRoots=[],selectedCapabilityRoots=[],allowProviderModelFallback=False,
            experimentalRawEvents=False,dynamicTools=[{'type':'function','name':'rnr_command',
                'description':'Execute one bounded offline argv command','deferLoading':False,
                'inputSchema':{'type':'object','properties':{'argv':{'type':'array','items':{'type':'string'},
                    'minItems':1,'maxItems':bounds.arguments}},'required':['argv'],'additionalProperties':False}}])
    else: raise ValueError('unknown bootstrap request')
    raw=json.dumps({'id':wire_id,'method':method,'params':params},allow_nan=False,separators=(',',':')).encode()+b'\n'
    if len(raw)-1>bounds.frame_bytes: raise ValueError('bootstrap frame bound')
    return raw


class BootstrapAdapter:
    def __init__(self,*args,**kwargs):
        raise RuntimeError('operational bootstrap disabled; use explicit synthetic factory')

    @classmethod
    def for_synthetic(cls, controller, ops, spec, bounds):
        from .control_transport import Bounds
        _spec(spec)
        if (type(bounds) is not Bounds or getattr(ops, 'synthetic_only', False) is not True or
                not callable(getattr(ops, 'bind_channel', None))):
            raise ValueError('bounded explicit synthetic bootstrap ops required')
        if any(not callable(getattr(controller,name,None)) for name in
               ('prepare_binding','start_ownership_ack','acknowledge')):
            raise ValueError('bootstrap controller interface required')
        self=object.__new__(cls)
        self.controller,self.ops,self.spec,self.bounds=controller,ops,spec,bounds
        self._ticket=None; self._channel_claimed=False
        return self

    def begin(self):
        return self.controller.prepare_binding(self.spec)

    def start_ownership_ack(self):
        return self.controller.start_ownership_ack(self.spec.packet.key.assignment)

    def acknowledge(self,ack):
        return self.controller.acknowledge(ack)

    def bind_channel(self,ticket,evidence):
        from .control_store import RuntimeTicket, RuntimeEvidence
        if type(ticket) is not RuntimeTicket or type(evidence) is not RuntimeEvidence:
            raise ValueError('typed committed runtime evidence required')
        validate_record(ticket); validate_record(evidence)
        if self._channel_claimed: raise ValueError('channel already consumed; no retry')
        if (ticket.spec_digest!=record_digest(self.spec) or ticket.key!=self.spec.packet.key or
                ticket.packet_digest!=self.spec.packet.packet_digest or evidence.ticket_id!=ticket.id or
                evidence.instance.allocation!=ticket.allocation or evidence.instance.name!=ticket.name or
                evidence.instance.labels!=ticket.labels or evidence.connection!=ticket.key.connection or
                evidence.generation!=ticket.key.generation):
            raise ValueError('private channel runtime identity mismatch')
        # Claim before invoking even the fake callback: lost bind never retries.
        self._channel_claimed=True
        channel=self.ops.bind_channel(ticket,evidence)
        if (getattr(channel,'synthetic_only',False) is not True or
                getattr(channel,'channel_ref',None)!=evidence.channel_ref or
                getattr(channel,'runtime_evidence',None)!=evidence or
                any(not callable(getattr(channel,name,None)) for name in ('write','read'))):
            raise ValueError('private synthetic channel mismatch')
        self._ticket=ticket
        return channel

    def next_action(self,state,validated_event):
        """Pure reducer. Controller commits expectations/observations before I/O.

        Repeated calls return the same action, never execute it. Store one-shot
        transitions are mandatory; this reducer cannot grant replay authority.
        """
        if self._ticket is None: raise ValueError('bind committed runtime channel first')
        if state=='reserved':
            if validated_event is not None: raise ValueError('unexpected initial response')
            step='initialize'; response=None; prefix=()
        elif state in ('initialize','config_read','thread_start'):
            if type(validated_event) is not dict: raise ValueError('validated response required')
            raw=json.dumps(validated_event,allow_nan=False,separators=(',',':')).encode()
            response=validate_bootstrap_response(state,raw,self.spec)
            if response['id']!=self.wire_id(state): raise ValueError('bootstrap step correlation mismatch')
            if state=='thread_start': return BootstrapAction('bound',(),None,response)
            step='config_read' if state=='initialize' else 'thread_start'
            prefix=(b'{"method":"initialized"}\n',) if state=='initialize' else ()
        else: raise ValueError('closed bootstrap reducer state required')
        frame=build_bootstrap_request(step,self.wire_id(step),self.spec,self.bounds)
        return BootstrapAction(step,prefix+(frame,),step,response)

    def wire_id(self,step):
        if self._ticket is None or step not in ('initialize','config_read','thread_start'):
            raise ValueError('bound bootstrap step required')
        return 'bootstrap:'+self._ticket.id+':'+step


# Frozen validation-only projection of B/v2/ConfigReadResponse.json definitions.
# SHA256 4ec77e1a3eed746037149799c3b6bb8fe7b4b593e5930fc9f410e6282de9df50
# Documentation/default annotations removed; constraints retained. No file loader.
_CONFIG_DEFINITIONS = {'AbsolutePathBuf': {'type': 'string'},
 'AllowDenyRequirement': {'enum': ['allow', 'deny'], 'type': 'string'},
 'AnalyticsConfig': {'additionalProperties': True,
                     'properties': {'enabled': {'type': ['boolean', 'null']}},
                     'type': 'object'},
 'AppConfig': {'properties': {'approvals_reviewer': {'anyOf': [{'$ref': '#/definitions/ApprovalsReviewer'},
                                                               {'type': 'null'}]},
                              'default_tools_approval_mode': {'anyOf': [{'$ref': '#/definitions/AppToolApproval'},
                                                                        {'type': 'null'}]},
                              'default_tools_enabled': {'type': ['boolean', 'null']},
                              'destructive_enabled': {'type': ['boolean', 'null']},
                              'enabled': {'type': 'boolean'},
                              'links': {'anyOf': [{'$ref': '#/definitions/AppLinksConfig'},
                                                  {'type': 'null'}]},
                              'omit_tools_from': {'items': {'$ref': '#/definitions/ToolExposureSurface'},
                                                  'type': ['array', 'null']},
                              'open_world_enabled': {'type': ['boolean', 'null']},
                              'tools': {'anyOf': [{'$ref': '#/definitions/AppToolsConfig'},
                                                  {'type': 'null'}]}},
               'type': 'object'},
 'AppLinkConfig': {'properties': {'approvals_reviewer': {'anyOf': [{'$ref': '#/definitions/ApprovalsReviewer'},
                                                                   {'type': 'null'}]},
                                  'default_tools_approval_mode': {'anyOf': [{'$ref': '#/definitions/AppToolApproval'},
                                                                            {'type': 'null'}]}},
                   'type': 'object'},
 'AppLinksConfig': {'type': 'object'},
 'AppToolApproval': {'enum': ['auto', 'prompt', 'writes', 'approve'], 'type': 'string'},
 'AppToolConfig': {'properties': {'approval_mode': {'anyOf': [{'$ref': '#/definitions/AppToolApproval'},
                                                              {'type': 'null'}]},
                                  'enabled': {'type': ['boolean', 'null']}},
                   'type': 'object'},
 'AppToolsConfig': {'type': 'object'},
 'ApprovalsReviewer': {'enum': ['user', 'auto_review', 'guardian_subagent'], 'type': 'string'},
 'AppsConfig': {'properties': {'_default': {'anyOf': [{'$ref': '#/definitions/AppsDefaultConfig'},
                                                      {'type': 'null'}]}},
                'type': 'object'},
 'AppsDefaultConfig': {'properties': {'approvals_reviewer': {'anyOf': [{'$ref': '#/definitions/ApprovalsReviewer'},
                                                                       {'type': 'null'}]},
                                      'default_tools_approval_mode': {'anyOf': [{'$ref': '#/definitions/AppToolApproval'},
                                                                                {'type': 'null'}]},
                                      'destructive_enabled': {'type': 'boolean'},
                                      'enabled': {'type': 'boolean'},
                                      'open_world_enabled': {'type': 'boolean'}},
                       'type': 'object'},
 'AskForApproval': {'oneOf': [{'enum': ['untrusted', 'on-request', 'never'], 'type': 'string'},
                              {'additionalProperties': False,
                               'properties': {'granular': {'properties': {'mcp_elicitations': {'type': 'boolean'},
                                                                          'request_permissions': {'type': 'boolean'},
                                                                          'rules': {'type': 'boolean'},
                                                                          'sandbox_approval': {'type': 'boolean'},
                                                                          'skill_approval': {'type': 'boolean'}},
                                                           'required': ['mcp_elicitations',
                                                                        'rules',
                                                                        'sandbox_approval'],
                                                           'type': 'object'}},
                               'required': ['granular'],
                               'type': 'object'}]},
 'AutoCompactTokenLimitScope': {'oneOf': [{'enum': ['total'], 'type': 'string'},
                                          {'enum': ['body_after_prefix'], 'type': 'string'}]},
 'BrowserUseConfig': {'properties': {'allow_history_access': {'type': ['boolean', 'null']},
                                     'default_origin_policy': {'anyOf': [{'$ref': '#/definitions/BrowserUseOriginPolicyConfig'},
                                                                         {'type': 'null'}]},
                                     'origins': {'additionalProperties': {'$ref': '#/definitions/BrowserUseOriginPolicyConfig'},
                                                 'type': ['object', 'null']}},
                      'type': 'object'},
 'BrowserUseOriginPolicyConfig': {'properties': {'access': {'anyOf': [{'$ref': '#/definitions/AllowDenyRequirement'},
                                                                      {'type': 'null'}]},
                                                 'downloads': {'anyOf': [{'$ref': '#/definitions/AllowDenyRequirement'},
                                                                         {'type': 'null'}]},
                                                 'full_cdp_access': {'anyOf': [{'$ref': '#/definitions/AllowDenyRequirement'},
                                                                               {'type': 'null'}]},
                                                 'uploads': {'anyOf': [{'$ref': '#/definitions/AllowDenyRequirement'},
                                                                       {'type': 'null'}]}},
                                  'type': 'object'},
 'ComputerUseConfig': {'properties': {'default_app_access': {'anyOf': [{'$ref': '#/definitions/AllowDenyRequirement'},
                                                                       {'type': 'null'}]},
                                      'macos': {'anyOf': [{'$ref': '#/definitions/ComputerUseMacosConfig'},
                                                          {'type': 'null'}]},
                                      'windows': {'anyOf': [{'$ref': '#/definitions/ComputerUseWindowsConfig'},
                                                            {'type': 'null'}]}},
                       'type': 'object'},
 'ComputerUseMacosConfig': {'properties': {'bundle_ids': {'additionalProperties': {'$ref': '#/definitions/AllowDenyRequirement'},
                                                          'type': ['object', 'null']}},
                            'type': 'object'},
 'ComputerUseWindowsConfig': {'properties': {'aumids': {'additionalProperties': {'$ref': '#/definitions/AllowDenyRequirement'},
                                                        'type': ['object', 'null']},
                                             'exes': {'items': {'$ref': '#/definitions/ComputerUseWindowsExeConfig'},
                                                      'type': ['array', 'null']}},
                              'type': 'object'},
 'ComputerUseWindowsExeConfig': {'properties': {'access': {'$ref': '#/definitions/AllowDenyRequirement'},
                                                'binary_name': {'type': ['string', 'null']},
                                                'product_name': {'type': 'string'},
                                                'publisher_name': {'type': 'string'}},
                                 'required': ['access', 'product_name', 'publisher_name'],
                                 'type': 'object'},
 'Config': {'additionalProperties': True,
            'properties': {'analytics': {'anyOf': [{'$ref': '#/definitions/AnalyticsConfig'},
                                                   {'type': 'null'}]},
                           'approval_policy': {'anyOf': [{'$ref': '#/definitions/AskForApproval'},
                                                         {'type': 'null'}]},
                           'approvals_reviewer': {'anyOf': [{'$ref': '#/definitions/ApprovalsReviewer'},
                                                            {'type': 'null'}]},
                           'apps': {'anyOf': [{'$ref': '#/definitions/AppsConfig'}, {'type': 'null'}]},
                           'browser_use': {'anyOf': [{'$ref': '#/definitions/BrowserUseConfig'},
                                                     {'type': 'null'}]},
                           'compact_prompt': {'type': ['string', 'null']},
                           'computer_use': {'anyOf': [{'$ref': '#/definitions/ComputerUseConfig'},
                                                      {'type': 'null'}]},
                           'desktop': {'additionalProperties': True, 'type': ['object', 'null']},
                           'developer_instructions': {'type': ['string', 'null']},
                           'forced_chatgpt_workspace_id': {'anyOf': [{'$ref': '#/definitions/ForcedChatgptWorkspaceIds'},
                                                                     {'type': 'null'}]},
                           'forced_login_method': {'anyOf': [{'$ref': '#/definitions/ForcedLoginMethod'},
                                                             {'type': 'null'}]},
                           'instructions': {'type': ['string', 'null']},
                           'model': {'type': ['string', 'null']},
                           'model_auto_compact_token_limit': {'format': 'int64', 'type': ['integer', 'null']},
                           'model_auto_compact_token_limit_scope': {'anyOf': [{'$ref': '#/definitions/AutoCompactTokenLimitScope'},
                                                                              {'type': 'null'}]},
                           'model_context_window': {'format': 'int64', 'type': ['integer', 'null']},
                           'model_provider': {'type': ['string', 'null']},
                           'model_reasoning_effort': {'anyOf': [{'$ref': '#/definitions/ReasoningEffort'},
                                                                {'type': 'null'}]},
                           'model_reasoning_summary': {'anyOf': [{'$ref': '#/definitions/ReasoningSummary'},
                                                                 {'type': 'null'}]},
                           'model_verbosity': {'anyOf': [{'$ref': '#/definitions/Verbosity'},
                                                         {'type': 'null'}]},
                           'review_model': {'type': ['string', 'null']},
                           'sandbox_mode': {'anyOf': [{'$ref': '#/definitions/SandboxMode'},
                                                      {'type': 'null'}]},
                           'sandbox_workspace_write': {'anyOf': [{'$ref': '#/definitions/SandboxWorkspaceWrite'},
                                                                 {'type': 'null'}]},
                           'service_tier': {'type': ['string', 'null']},
                           'tools': {'anyOf': [{'$ref': '#/definitions/ToolsV2'}, {'type': 'null'}]},
                           'web_search': {'anyOf': [{'$ref': '#/definitions/WebSearchMode'},
                                                    {'type': 'null'}]}},
            'type': 'object'},
 'ConfigLayer': {'properties': {'config': True,
                                'disabledReason': {'type': ['string', 'null']},
                                'name': {'$ref': '#/definitions/ConfigLayerSource'},
                                'version': {'type': 'string'}},
                 'required': ['config', 'name', 'version'],
                 'type': 'object'},
 'ConfigLayerMetadata': {'properties': {'name': {'$ref': '#/definitions/ConfigLayerSource'},
                                        'version': {'type': 'string'}},
                         'required': ['name', 'version'],
                         'type': 'object'},
 'ConfigLayerSource': {'oneOf': [{'properties': {'file': {'allOf': [{'$ref': '#/definitions/AbsolutePathBuf'}]},
                                                 'type': {'enum': ['packagedDefaults'], 'type': 'string'}},
                                  'required': ['file', 'type'],
                                  'type': 'object'},
                                 {'properties': {'domain': {'type': 'string'},
                                                 'key': {'type': 'string'},
                                                 'type': {'enum': ['mdm'], 'type': 'string'}},
                                  'required': ['domain', 'key', 'type'],
                                  'type': 'object'},
                                 {'properties': {'file': {'allOf': [{'$ref': '#/definitions/AbsolutePathBuf'}]},
                                                 'type': {'enum': ['system'], 'type': 'string'}},
                                  'required': ['file', 'type'],
                                  'type': 'object'},
                                 {'properties': {'id': {'type': 'string'},
                                                 'name': {'type': 'string'},
                                                 'type': {'enum': ['enterpriseManaged'], 'type': 'string'}},
                                  'required': ['id', 'name', 'type'],
                                  'type': 'object'},
                                 {'properties': {'file': {'allOf': [{'$ref': '#/definitions/AbsolutePathBuf'}]},
                                                 'profile': {'type': ['string', 'null']},
                                                 'type': {'enum': ['user'], 'type': 'string'}},
                                  'required': ['file', 'type'],
                                  'type': 'object'},
                                 {'properties': {'dotCodexFolder': {'$ref': '#/definitions/AbsolutePathBuf'},
                                                 'type': {'enum': ['project'], 'type': 'string'}},
                                  'required': ['dotCodexFolder', 'type'],
                                  'type': 'object'},
                                 {'properties': {'type': {'enum': ['sessionFlags'], 'type': 'string'}},
                                  'required': ['type'],
                                  'type': 'object'},
                                 {'properties': {'file': {'$ref': '#/definitions/AbsolutePathBuf'},
                                                 'type': {'enum': ['legacyManagedConfigTomlFromFile'],
                                                          'type': 'string'}},
                                  'required': ['file', 'type'],
                                  'type': 'object'},
                                 {'properties': {'type': {'enum': ['legacyManagedConfigTomlFromMdm'],
                                                          'type': 'string'}},
                                  'required': ['type'],
                                  'type': 'object'}]},
 'ForcedChatgptWorkspaceIds': {'anyOf': [{'type': 'string'}, {'items': {'type': 'string'}, 'type': 'array'}]},
 'ForcedLoginMethod': {'enum': ['chatgpt', 'api'], 'type': 'string'},
 'ReasoningEffort': {'minLength': 1, 'type': 'string'},
 'ReasoningSummary': {'oneOf': [{'enum': ['auto', 'concise', 'detailed'], 'type': 'string'},
                                {'enum': ['none'], 'type': 'string'}]},
 'SandboxMode': {'enum': ['read-only', 'workspace-write', 'danger-full-access'], 'type': 'string'},
 'SandboxWorkspaceWrite': {'properties': {'exclude_slash_tmp': {'type': 'boolean'},
                                          'exclude_tmpdir_env_var': {'type': 'boolean'},
                                          'network_access': {'type': 'boolean'},
                                          'writable_roots': {'items': {'type': 'string'}, 'type': 'array'}},
                           'type': 'object'},
 'ToolExposureSurface': {'oneOf': [{'enum': ['code_mode'], 'type': 'string'},
                                   {'enum': ['deferred'], 'type': 'string'},
                                   {'enum': ['direct'], 'type': 'string'}]},
 'ToolsV2': {'properties': {'web_search': {'anyOf': [{'$ref': '#/definitions/WebSearchToolConfig'},
                                                     {'type': 'null'}]}},
             'type': 'object'},
 'Verbosity': {'enum': ['low', 'medium', 'high'], 'type': 'string'},
 'WebSearchContextSize': {'enum': ['low', 'medium', 'high'], 'type': 'string'},
 'WebSearchLocation': {'additionalProperties': False,
                       'properties': {'city': {'type': ['string', 'null']},
                                      'country': {'type': ['string', 'null']},
                                      'region': {'type': ['string', 'null']},
                                      'timezone': {'type': ['string', 'null']}},
                       'type': 'object'},
 'WebSearchMode': {'enum': ['disabled', 'cached', 'indexed', 'live'], 'type': 'string'},
 'WebSearchToolConfig': {'additionalProperties': False,
                         'properties': {'allowed_domains': {'items': {'type': 'string'},
                                                            'type': ['array', 'null']},
                                        'context_size': {'anyOf': [{'$ref': '#/definitions/WebSearchContextSize'},
                                                                   {'type': 'null'}]},
                                        'location': {'anyOf': [{'$ref': '#/definitions/WebSearchLocation'},
                                                               {'type': 'null'}]}},
                         'type': 'object'}}


def _schema(value, schema):
    """Evaluate only constructs present in the retained Config schema projection."""
    if schema is True: return
    if schema is False: raise ValueError('schema false')
    if '$ref' in schema:
        name=schema['$ref'].removeprefix('#/definitions/')
        _schema(value,_CONFIG_DEFINITIONS[name])
        if name=='AbsolutePathBuf':
            from .control_store import normalized_path
            normalized_path(value)
        return
    for variant in ('anyOf','oneOf'):
        if variant in schema:
            matches=0
            for child in schema[variant]:
                try: _schema(value,child)
                except ValueError: continue
                matches+=1
            if not matches or (variant=='oneOf' and matches!=1): raise ValueError('config schema variant')
    for child in schema.get('allOf',[]): _schema(value,child)
    if 'enum' in schema and not any(type(value) is type(v) and value==v for v in schema['enum']):
        raise ValueError('config schema enum')
    types=schema.get('type',[])
    if type(types) is str: types=[types]
    predicates={'object':lambda:type(value)is dict,'array':lambda:type(value)is list,
        'string':lambda:type(value)is str,'integer':lambda:type(value)is int,
        'number':lambda:type(value)in(int,float),'boolean':lambda:type(value)is bool,'null':lambda:value is None}
    if types and not any(predicates[t]() for t in types): raise ValueError('config schema type')
    if type(value) is dict and ('object' in types or any(k in schema for k in ('properties','required','additionalProperties'))):
        properties=schema.get('properties',{})
        if not set(schema.get('required',[]))<=value.keys(): raise ValueError('config required field')
        for k,v in value.items():
            if k in properties: _schema(v,properties[k])
            else: _schema(v,schema.get('additionalProperties',False))
    if type(value) is list:
        if len(value)<schema.get('minItems',0) or len(value)>schema.get('maxItems',4096): raise ValueError('config array bound')
        for child in value: _schema(child,schema.get('items',True))
    if type(value) is str:
        if len(value)<schema.get('minLength',0) or len(value)>schema.get('maxLength',MAX_FRAME):
            raise ValueError('config string bound')
    if type(value) is int:
        if schema.get('format')=='int64': int64(value)
        if schema.get('format')=='uint64' and not 0<=value<2**64: raise ValueError('uint64 bound')
        if value<schema.get('minimum',value) or value>schema.get('maximum',value): raise ValueError('config numeric bound')


@dataclass(frozen=True)
class BootstrapAction:
    next_state: str
    frames: tuple[bytes, ...]
    step: str | None
    response: dict | None = None
