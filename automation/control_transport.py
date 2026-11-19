"""Bounded source-only JSONL adapter. No process, SDK or operational launcher.

The caller supplies private byte I/O. ``feed`` belongs to its independent reader;
write belongs to a dedicated writer. The sink must consume the entire bytes
argument and return None (all-or-raise) or its exact byte count. Any other
return fences the transport; partial writes are not retried. Neither waits for controller/store/command
work. A separate supervisor must enforce writer deadlines and close owned pipes.
"""
# Positive lifecycle authority belongs exclusively to the serialized Store.
# Method spelling is bound to the saved pinned ServerNotification schema in tests.
SUPPORTED_NOTIFICATIONS = frozenset({'turn/completed'})
PINNED_NOTIFICATIONS = frozenset({
    'thread/started', 'thread/status/changed', 'thread/tokenUsage/updated',
    'turn/started', 'turn/completed', 'turn/plan/updated', 'item/started',
    'item/completed', 'item/agentMessage/delta', 'item/plan/delta',
    'item/reasoning/summaryTextDelta', 'item/reasoning/summaryPartAdded',
    'item/reasoning/textDelta', 'warning'})

from dataclasses import dataclass
import json
import hashlib
import math
import queue
import threading
import time


@dataclass(frozen=True)
class Bounds:
    frame_bytes: int
    argument_bytes: int
    arguments: int
    input_queue: int
    output_queue: int
    identities: int

    def __post_init__(self):
        if any(type(v) is not int or not 0 < v <= 1_048_576 for v in vars(self).values()):
            raise ValueError('explicit positive finite wire bounds required')


@dataclass(frozen=True)
class Event:
    kind: str
    message: dict
    raw: bytes


def _identifier(value):
    if type(value) is int:
        return -(2**63) <= value < 2**63
    return _text(value)


def _text(value):
    try:
        turn_id(value)
        return True
    except ValueError:
        return False


def decode(raw):
    def unique(pairs):
        result = {}
        for k, v in pairs:
            if k in result:
                raise ValueError('duplicate key')
            result[k] = v
        return result
    def nonfinite(_):
        raise ValueError('nonfinite number')
    def number(value):
        result = float(value)
        if not math.isfinite(result):
            raise ValueError('nonfinite number')
        return result
    return json.loads(raw.decode('utf-8'), object_pairs_hook=unique,
                      parse_constant=nonfinite, parse_float=number)


def command_params(params, bounds):
    if type(params) is not dict or set(params) != {'threadId', 'turnId', 'callId', 'tool', 'arguments'}:
        raise ValueError('exact dynamic call params required')
    if any(not _text(params[k]) for k in ('threadId', 'turnId', 'callId')):
        raise ValueError('invalid dynamic identity')
    if params['tool'] != 'rnr_command':
        raise ValueError('tool refused')
    args = params['arguments']
    if type(args) is not dict or set(args) != {'argv'}:
        raise ValueError('argv-only arguments required')
    argv = args['argv']
    if (type(argv) is not list or not 0 < len(argv) <= bounds.arguments or
            any(type(s) is not str or '\x00' in s for s in argv) or not argv[0]):
        raise ValueError('invalid argv')
    if sum(len(s.encode('utf-8')) for s in argv) > bounds.argument_bytes:
        raise ValueError('argument byte limit')
    return params


def turn_id(value):
    if (type(value) is not str or not value or
            any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value)):
        raise ValueError('bounded control-free turn identity required')
    try:
        if len(value.encode('utf-8')) > 256:
            raise ValueError('turn identity byte limit')
    except UnicodeError as error:
        raise ValueError('invalid UTF-8 identity') from error
    return value


def bounded_text(value, limit, *, nonempty=False):
    if type(value) is not str or (nonempty and (not value or '\x00' in value)):
        raise ValueError('bounded plain text required')
    try:
        if len(value.encode('utf-8')) > limit:
            raise ValueError('text byte limit')
    except UnicodeError as error:
        raise ValueError('invalid UTF-8 text') from error
    return value


def _policy(policy):
    from .control_store import TurnPolicy
    if type(policy) is not TurnPolicy:
        raise ValueError('protected TurnPolicy required')
    policy.validate()


def build_turn_start(ticket, text, policy, bounds):
    """Fixed wire subset; ticket authority is checked by Controller/Store."""
    from .control_store import finite, positive
    _policy(policy)
    if type(ticket) is not dict or set(ticket) != {
            'id', 'assignment', 'epoch', 'owner_version', 'connection', 'generation',
            'thread', 'intent', 'wire_id', 'input_hash', 'policy_hash', 'deadline', 'purpose'}:
        raise ValueError('exact committed turn ticket required')
    if ticket['purpose'] not in ('work', 'ownership_ack'):
        raise ValueError('committed purpose required')
    for key in ('assignment', 'connection', 'generation', 'thread', 'intent', 'wire_id'):
        turn_id(ticket[key])
    for key in ('id', 'input_hash', 'policy_hash'):
        if (type(ticket[key]) is not str or len(ticket[key]) != 64 or
                any(c not in '0123456789abcdef' for c in ticket[key])):
            raise ValueError('invalid turn fingerprint')
    positive(ticket['epoch']); positive(ticket['owner_version']); finite(ticket['deadline'])
    bounded_text(text, policy.input_bytes, nonempty=True)
    if (hashlib.sha256(text.encode('utf-8')).hexdigest() != ticket['input_hash'] or
            policy.fingerprint() != ticket['policy_hash']):
        raise ValueError('turn ticket fingerprint mismatch')
    frame = {'id': ticket['wire_id'], 'method': 'turn/start', 'params': {
        'threadId': ticket['thread'], 'input': [{'type': 'text', 'text': text, 'text_elements': []}],
        'environments': [], 'approvalPolicy': 'never', 'sandboxPolicy': {'type': 'dangerFullAccess'},
        'model': policy.model, 'effort': policy.effort, 'runtimeWorkspaceRoots': []}}
    raw = json.dumps(frame, allow_nan=False, separators=(',', ':')).encode('utf-8') + b'\n'
    if len(raw) - 1 > bounds.frame_bytes:
        raise ValueError('oversized turn frame')
    return raw


def _turn(turn, policy, *, terminal=False, bounds=None, purpose="work"):
    from .control_store import canonical
    _policy(policy)
    required = {'id', 'items', 'status'}
    optional = {'error', 'itemsView', 'rootTurnId', 'startedAt', 'completedAt', 'durationMs'}
    if type(turn) is not dict or not required <= set(turn) or set(turn) - required - optional:
        raise ValueError('closed turn object required')
    turn_id(turn['id'])
    statuses = ('completed', 'failed', 'interrupted') if terminal else ('inProgress', 'completed', 'failed', 'interrupted')
    if turn['status'] not in statuses:
        raise ValueError('invalid turn status')
    items = turn['items']
    if type(items) is not list or len(items) > policy.turn_items:
        raise ValueError('bounded turn items required')
    item_ids = set()
    for item in items:
        validate_item(item, policy, bounds, purpose=purpose)
        if item['id'] in item_ids:
            raise ValueError('duplicate turn item identity')
        item_ids.add(item['id'])
    if 'itemsView' in turn:
        if turn['itemsView'] not in ('notLoaded', 'summary', 'full') or (turn['itemsView'] == 'notLoaded' and items):
            raise ValueError('invalid items view')
    if turn.get('rootTurnId') is not None:
        turn_id(turn['rootTurnId'])
    for key in ('startedAt', 'completedAt', 'durationMs'):
        value = turn.get(key)
        if value is not None and (type(value) is not int or not -(2**63) <= value < 2**63 or
                                  (key == 'durationMs' and value < 0)):
            raise ValueError('invalid turn time observation')
    error = turn.get('error')
    if error is not None:
        if (turn['status'] in ('inProgress', 'completed') or type(error) is not dict or
                'message' not in error or set(error) - {'message', 'additionalDetails', 'codexErrorInfo', 'misalignment'} or
                error.get('codexErrorInfo') is not None or error.get('misalignment') is not None):
            raise ValueError('closed turn error subset required')
        bounded_text(error['message'], policy.item_text_bytes)
        if error.get('additionalDetails') is not None:
            bounded_text(error['additionalDetails'], policy.item_text_bytes)
    return turn['id'], turn['status'], hashlib.sha256(canonical(turn).encode('utf-8')).hexdigest()


def parse_turn_response(message, policy, *, bounds=None, purpose="work"):
    from .control_bootstrap import bounded_json
    bounded_json(message)
    if (type(message) is not dict or set(message) != {'id', 'result'} or
            not _identifier(message['id']) or type(message['result']) is not dict or
            set(message['result']) != {'turn'}):
        raise ValueError('exact turn start success required')
    return _turn(message['result']['turn'], policy, bounds=bounds, purpose=purpose)


def parse_turn_notification(message, policy, *, bounds=None, purpose="work"):
    from .control_bootstrap import bounded_json
    bounded_json(message)
    if (type(message) is not dict or not {'method', 'params'} <= set(message) or
            set(message) - {'method', 'params', 'emittedAtMs'} or
            message['method'] != 'turn/completed' or type(message['params']) is not dict or
            set(message['params']) != {'threadId', 'turn'}):
        raise ValueError('exact turn completion required')
    if 'emittedAtMs' in message:
        from .control_bootstrap import int64
        int64(message['emittedAtMs'])
    return (turn_id(message['params']['threadId']), *_turn(message['params']['turn'], policy, terminal=True, bounds=bounds, purpose=purpose))


class Transport:
    def __init__(self, bounds, write, fence, *, policy=None, terminal_ingress=None, observation_profile=None):
        if observation_profile is not None:
            _policy(policy)
            if (type(observation_profile) is not ObservationProfile or
                    observation_profile.wire_bounds != bounds or
                    policy.model != observation_profile.spec.model or policy.effort != observation_profile.spec.effort):
                raise ValueError('matching protected observation profile required')
        self.bounds, self._write, self._fence = bounds, write, fence
        self.policy, self._terminal_ingress = policy, terminal_ingress
        self.observation_profile = observation_profile
        self._writes_stopped = threading.Event()
        self.events = queue.Queue(bounds.input_queue)
        self._output = queue.Queue(bounds.output_queue)
        self._buffer = bytearray()
        self._incoming, self._outgoing = set(), {}
        self._used_outgoing = set()
        self._replied = set()
        self._ids_lock = threading.Lock()
        self._stopped = threading.Event()
        self.writing_since = None
        self._writer = threading.Thread(target=self._write_loop, daemon=True, name='control-writer')
        self._writer.start()

    def fail(self, reason):
        if not self._stopped.is_set():
            self._stopped.set()
            self._fence(reason)

    def expect_response(self, identity, *, kind="turn"):
        with self._ids_lock:
            key = (type(identity).__name__, identity)
            if (not _identifier(identity) or key in self._used_outgoing or
                    len(self._used_outgoing) >= self.bounds.identities or
                    kind not in ("turn", "bootstrap") or
                    (kind == "bootstrap" and "bootstrap" in self._outgoing.values())):
                raise ValueError('invalid outbound correlation')
            self._outgoing[key] = kind
            self._used_outgoing.add(key)

    def feed(self, data):
        """Reader-only, bounded nonblocking ingestion; no storage or RPC waits."""
        if self._stopped.is_set():
            return
        if type(data) is not bytes:
            self.fail('invalid reader bytes'); return
        # Consume incrementally so a huge input cannot enlarge the retained frame.
        for byte in data:
            if byte != 10:
                self._buffer.append(byte)
                if len(self._buffer) > self.bounds.frame_bytes:
                    self.fail('oversized frame'); self._buffer.clear(); return
                continue
            raw = bytes(self._buffer)
            self._buffer.clear()
            try:
                event = self._parse(raw)
                if event.kind == 'notification' and self.policy is not None:
                    if self.observation_profile is not None:
                        observed = parse_observation(event, self.policy, self.observation_profile)
                        terminal = observed.terminal
                    else:
                        terminal = parse_turn_notification(event.message, self.policy)
                    if terminal is not None and self._terminal_ingress is not None and self._terminal_ingress(terminal):
                        continue
                self.events.put_nowait(event)
            except (ValueError, UnicodeError, RecursionError, queue.Full) as error:
                self.fail(type(error).__name__ + ': invalid wire or saturated handoff')
                return

    def _parse(self, raw):
        message = decode(raw)
        from .control_bootstrap import bounded_json
        bounded_json(message, self.bounds.frame_bytes)
        if type(message) is not dict:
            raise ValueError('object envelope required')
        if 'method' in message:
            if (type(message['method']) is not str or not _text(message['method']) or
                    type(message.get('params')) is not dict):
                raise ValueError('method/object params required')
            if 'id' not in message:
                if (not {'method', 'params'} <= set(message) or
                        set(message) - {'method', 'params', 'emittedAtMs'}):
                    raise ValueError('notification envelope')
                if 'emittedAtMs' in message:
                    from .control_bootstrap import int64
                    int64(message['emittedAtMs'])
                routes = PINNED_NOTIFICATIONS if self.observation_profile is not None else SUPPORTED_NOTIFICATIONS
                if message['method'] not in routes:
                    raise ValueError('unknown notification route')
                return Event('notification', message, raw)
            if set(message) != {'id', 'method', 'params'} or not _identifier(message['id']):
                raise ValueError('request envelope')
            key = (type(message['id']).__name__, message['id'])
            if key in self._incoming or len(self._incoming) >= self.bounds.identities:
                raise ValueError('duplicate/exhausted inbound identity')
            if message['method'] != 'item/tool/call':
                # Refuse by fencing the private transport, never default success.
                raise ValueError('retained built-in or unknown request refused')
            command_params(message['params'], self.bounds)
            if self.observation_profile is not None:
                self.observation_profile.command_request(message['params'])
            self._incoming.add(key)
            return Event('request', message, raw)
        if (set(message) not in ({'id', 'result'}, {'id', 'error'}) or
                not _identifier(message.get('id'))):
            raise ValueError('response envelope')
        key = (type(message['id']).__name__, message['id'])
        with self._ids_lock:
            if key not in self._outgoing:
                raise ValueError('unregistered response')
            kind = self._outgoing.pop(key)
        if 'error' in message:
            raise ValueError('wire error response; dispatched outcome UNKNOWN')
        return Event('bootstrap_response' if kind == 'bootstrap' else 'response', message, raw)

    def eof(self):
        self.fail('transport EOF')

    def stop_writes(self):
        self._writes_stopped.set()

    def send_raw(self, raw):
        if self._stopped.is_set() or self._writes_stopped.is_set():
            return False
        try:
            if type(raw) is not bytes or not raw.endswith(b'\n') or len(raw) - 1 > self.bounds.frame_bytes:
                raise ValueError('invalid bounded output frame')
            if self.observation_profile is not None:
                self._validate_output(raw)
            self._output.put_nowait(raw)
            return True
        except (ValueError, UnicodeError, TypeError, RecursionError, queue.Full):
            self.fail('writer output overflow/invalid'); return False

    def send(self, message):
        try:
            raw = json.dumps(message, allow_nan=False, separators=(',', ':')).encode() + b'\n'
            return self.send_raw(raw)
        except (ValueError, UnicodeError, TypeError, RecursionError):
            self.fail('invalid output'); return False

    def _validate_output(self, raw):
        from .control_bootstrap import build_bootstrap_request, closed, bounded_json
        message=decode(raw); bounded_json(message,self.bounds.frame_bytes)
        if message=={'method':'initialized'}: return
        if type(message) is not dict: raise ValueError('outbound object')
        if 'method' in message:
            closed(message,{'id','method','params'})
            identity=message['id']; key=(type(identity).__name__,identity)
            if not _identifier(identity): raise ValueError('outbound identity')
            method=message['method']
            with self._ids_lock:
                expected_kind=self._outgoing.get(key)
            steps={'initialize':'initialize','config/read':'config_read','thread/start':'thread_start'}
            if type(method) is not str: raise ValueError('outbound method')
            if method in steps:
                if expected_kind!='bootstrap': raise ValueError('bootstrap correlation class')
                expected=decode(build_bootstrap_request(steps[method],identity,self.observation_profile.spec,self.bounds))
                from .control_store import canonical
                if canonical(message)!=canonical(expected): raise ValueError('fixed bootstrap frame required')
            elif method=='turn/start':
                if expected_kind!='turn': raise ValueError('turn correlation class')
                params=message['params']
                closed(params,{'threadId','input','environments','approvalPolicy','sandboxPolicy','model','effort','runtimeWorkspaceRoots'})
                turn_id(params['threadId'])
                expected={'environments':[],'approvalPolicy':'never','sandboxPolicy':{'type':'dangerFullAccess'},
                          'model':self.policy.model,'effort':self.policy.effort,'runtimeWorkspaceRoots':[]}
                if any(type(params[k]) is not type(v) or params[k]!=v for k,v in expected.items()): raise ValueError('fixed turn policy')
                inputs=params['input']
                if type(inputs) is not list or len(inputs)!=1: raise ValueError('single text input')
                closed(inputs[0],{'type','text','text_elements'})
                if inputs[0]['type']!='text' or inputs[0]['text_elements']!=[]: raise ValueError('plain turn input')
                bounded_text(inputs[0]['text'],self.policy.input_bytes,nonempty=True)
            else: raise ValueError('unselected outbound route')
        else:
            closed(message,{'id','result'})
            if not _identifier(message['id']): raise ValueError('reply identity')
            key=(type(message['id']).__name__,message['id'])
            if key not in self._incoming or key in self._replied: raise ValueError('uncorrelated/repeated reply')
            result=message['result']; closed(result,{'success','contentItems'})
            if type(result['success']) is not bool or type(result['contentItems']) is not list:
                raise ValueError('tool reply types')
            if len(result['contentItems'])>self.policy.turn_items: raise ValueError('tool reply count')
            for item in result['contentItems']:
                closed(item,{'type','text'})
                if item['type']!='inputText': raise ValueError('tool reply media')
                bounded_text(item['text'],self.bounds.frame_bytes)
            self._replied.add(key)

    def reply(self, identity, result):
        return self.send({'id': identity, 'result': result})

    def _write_loop(self):
        while not self._stopped.is_set():
            try:
                raw = self._output.get(timeout=.02)
            except queue.Empty:
                continue
            if self._stopped.is_set() or self._writes_stopped.is_set():
                continue
            self.writing_since = time.monotonic()
            try:
                written = self._write(raw)
                # None means an explicit all-or-raise sink (e.g. list.append).
                # Count-returning sinks must report the entire frame; partial,
                # zero and malformed counts fence, never silently drop a suffix.
                if written is not None and (type(written) is not int or written != len(raw)):
                    self.fail('incomplete or invalid byte-sink write')
            except Exception:
                self.fail('writer failure')
            finally:
                self.writing_since = None

    def writer_healthy(self, now, timeout):
        return (not self._stopped.is_set() and self._writer.is_alive() and
                (self.writing_since is None or now - self.writing_since <= timeout))

    def close(self):
        self._stopped.set()
        if threading.current_thread() is not self._writer:
            self._writer.join(.1)


def validate_item(item, policy, bounds=None, *, purpose='work'):
    """Pinned N#/definitions/ThreadItem selected discriminants only."""
    from .control_bootstrap import closed, int64
    if type(item) is not dict: raise ValueError('item object required')
    kind=item.get('type')
    variants={
        'agentMessage':({'id','type','text'},{'delivery','memoryCitation','phase','questions'}),
        'userMessage':({'id','type','content'},{'clientId'}),
        'reasoning':({'id','type'},{'summary','content'}),
        'plan':({'id','type','text'},set()),
        'dynamicToolCall':({'id','type','tool','arguments','status'},
                           {'namespace','durationMs','success','contentItems'})}
    if type(kind) is not str or kind not in variants: raise ValueError('unselected effectful item')
    closed(item,*variants[kind]); turn_id(item['id'])
    if kind in ('agentMessage','plan'):
        bounded_text(item['text'],policy.item_text_bytes)
        if kind=='agentMessage' and any(item.get(k) is not None for k in variants[kind][1]):
            raise ValueError('plain agent message required')
    elif kind=='reasoning':
        for key in ('summary','content'):
            values=item.get(key,[])
            if type(values) is not list or len(values)>policy.turn_items: raise ValueError('bounded reasoning required')
            for value in values: bounded_text(value,policy.item_text_bytes)
    elif kind=='userMessage':
        if item.get('clientId') is not None: raise ValueError('unselected client identity')
        content=item['content']
        if type(content) is not list or len(content)>policy.turn_items: raise ValueError('bounded user input required')
        for value in content:
            closed(value,{'type','text'},{'text_elements'})
            if value['type']!='text' or value.get('text_elements',[])!=[]: raise ValueError('plain text input required')
            bounded_text(value['text'],policy.item_text_bytes)
    else:
        if purpose=='ownership_ack': raise ValueError('dynamic item during ownership ACK')
        if item.get('namespace') is not None: raise ValueError('unselected tool namespace')
        if bounds is None:
            bounds=Bounds(1_048_576,policy.item_text_bytes,policy.turn_items,1,1,1)
        command_params(dict(threadId='item',turnId='item',callId=item['id'],tool=item['tool'],arguments=item['arguments']),bounds)
        if item['status'] not in ('inProgress','completed','failed'): raise ValueError('dynamic status')
        success=item.get('success')
        if success is not None and (type(success) is not bool or item['status']=='inProgress' or
                success != (item['status']=='completed')): raise ValueError('dynamic terminal consistency')
        if item.get('durationMs') is not None: int64(item['durationMs'],nonnegative=True)
        contents=item.get('contentItems')
        if contents is not None:
            if type(contents) is not list or len(contents)>policy.turn_items: raise ValueError('bounded tool content')
            for content in contents:
                closed(content,{'type','text'})
                if content['type']!='inputText': raise ValueError('tool media refused')
                bounded_text(content['text'],policy.item_text_bytes)
    return item


@dataclass(frozen=True)
class WireObservation:
    method: str
    message: dict
    pending: bool
    terminal: tuple | None = None


class ObservationProfile:
    """One private generation's bounded observations, never positive authority.

    Controller calls lifecycle methods only after corresponding Store commits.
    Reader parsing never calls Store, writes, callbacks or external operations.
    """
    def __init__(self, spec, bounds, wire_bounds):
        from .control_store import ObservationBounds, validate_record
        from .control_bootstrap import _spec
        _spec(spec)
        if type(bounds) is not ObservationBounds or type(wire_bounds) is not Bounds:
            raise ValueError('protected observation/wire bounds required')
        validate_record(bounds)
        self.spec,self.bounds,self.wire_bounds=spec,bounds,wire_bounds
        self._lock=threading.RLock()
        self._thread=None; self._candidate=None
        self._intents={}; self._servers={}; self._items={}; self._calls={}
        self._events=0; self._text=0; self._pending=0; self._totals={}
        self.warning=None

    @staticmethod
    def _thread_identity(thread):
        return {k:v for k,v in thread.items() if k not in ('createdAt','updatedAt','recencyAt','status')}

    def bind_thread(self, thread):
        from .control_bootstrap import validate_thread
        validate_thread(thread,self.spec)
        identity=self._thread_identity(thread)
        with self._lock:
            if ((self._thread is not None and self._thread!=identity) or
                    (self._candidate is not None and self._candidate!=identity)):
                raise ValueError('contradictory fresh thread evidence')
            self._thread=identity

    def dispatched(self, intent, purpose='work'):
        turn_id(intent)
        if purpose not in ('work','ownership_ack'): raise ValueError('turn purpose')
        with self._lock:
            if self._thread is None or intent in self._intents or len(self._intents)>=self.wire_bounds.identities:
                raise ValueError('unbound/reused/exhausted dispatch')
            self._intents[intent]={'purpose':purpose,'server':None,'candidate':None,'active':True,'pending':0}

    def accepted(self, intent, server_turn):
        turn_id(server_turn)
        with self._lock:
            record=self._intents.get(intent)
            if (record is None or (record['server'] is not None and record['server']!=server_turn) or
                    (record['candidate'] is not None and record['candidate']!=server_turn) or
                    (server_turn in self._servers and self._servers[server_turn]!=intent)):
                raise ValueError('response does not bind staged dispatch')
            self._pending-=record['pending']; record['pending']=0
            record['server']=server_turn; self._servers[server_turn]=intent

    def completed(self, server_turn):
        with self._lock:
            if server_turn not in self._servers: raise ValueError('unknown terminal binding')
            self._intents[self._servers[server_turn]]['active']=False

    def _correlate(self, thread, server, *, terminal=False):
        turn_id(thread); turn_id(server)
        if self._thread is None or self._thread['id']!=thread: raise ValueError('observation thread mismatch')
        intent=self._servers.get(server)
        if intent is not None:
            record=self._intents[intent]
            if not record['active'] and not terminal: raise ValueError('observation after turn closure')
            return record,False
        pending=[r for r in self._intents.values() if r['server'] is None and r['active']]
        if len(pending)!=1 or pending[0]['candidate'] not in (None,server):
            raise ValueError('unknown or ambiguous observed server turn')
        if self._pending>=self.bounds.max_pending_items: raise ValueError('pending observation bound')
        pending[0]['candidate']=server; pending[0]['pending']+=1; self._pending+=1
        return pending[0],True

    def command_request(self, params):
        with self._lock:
            record,pending=self._correlate(params['threadId'],params['turnId'])
            if pending or record['purpose']!='work': raise ValueError('unaccepted or ACK command')
            identity=(params['turnId'],params['callId'])
            value=(params['tool'],params['arguments'])
            if identity in self._calls and self._calls[identity]!=value: raise ValueError('dynamic call contradiction')
            if len(self._calls)>=self.bounds.max_pending_items and identity not in self._calls: raise ValueError('call observation bound')
            self._calls[identity]=value

    def _item(self, item, policy, purpose, server):
        validate_item(item,policy,self.wire_bounds,purpose=purpose)
        identity=(server,item['id'])
        if identity not in self._items:
            if len(self._items)>=self.bounds.max_pending_items: raise ValueError('aggregate item bound')
            self._items[identity]=item['type']
        elif self._items[identity]!=item['type']: raise ValueError('item discriminant changed')
        if item['type']=='dynamicToolCall':
            value=(item['tool'],item['arguments'])
            if identity in self._calls and self._calls[identity]!=value: raise ValueError('dynamic observation contradiction')
            if len(self._calls)>=self.bounds.max_pending_items and identity not in self._calls: raise ValueError('call bound')
            self._calls[identity]=value


def parse_observation(event, policy, profile):
    """N pinned notification roots and selected recursive profile from Annex A."""
    from .control_bootstrap import closed, int64, bounded_json, validate_thread
    if type(profile) is not ObservationProfile: raise ValueError('protected observation profile required')
    _policy(policy)
    if policy.model!=profile.spec.model or policy.effort!=profile.spec.effort: raise ValueError('policy mismatch')
    message=event.message
    closed(message,{'method','params'},{'emittedAtMs'})
    if 'emittedAtMs' in message: int64(message['emittedAtMs'])
    method=message['method']; params=message['params']
    required={
        'thread/started':{'thread'}, 'thread/status/changed':{'status','threadId'},
        'thread/tokenUsage/updated':{'threadId','turnId','tokenUsage'},
        'turn/started':{'threadId','turn'},'turn/completed':{'threadId','turn'},
        'turn/plan/updated':{'threadId','turnId','plan'},
        'item/started':{'threadId','turnId','item','startedAtMs'},
        'item/completed':{'threadId','turnId','item','completedAtMs'},
        'item/agentMessage/delta':{'threadId','turnId','itemId','delta'},
        'item/plan/delta':{'threadId','turnId','itemId','delta'},
        'item/reasoning/summaryTextDelta':{'threadId','turnId','itemId','summaryIndex','delta'},
        'item/reasoning/summaryPartAdded':{'threadId','turnId','itemId','summaryIndex'},
        'item/reasoning/textDelta':{'threadId','turnId','itemId','contentIndex','delta'},
        'warning':{'message'}}
    if type(method) is not str or method not in required: raise ValueError('unknown notification')
    optional={'explanation'} if method=='turn/plan/updated' else {'threadId'} if method=='warning' else set()
    closed(params,required[method],optional)
    with profile._lock:
        profile._events+=1
        profile._text+=bounded_json(message,profile.wire_bounds.frame_bytes)
        if profile._events>profile.bounds.events_per_generation or profile._text>profile.bounds.aggregate_text_bytes:
            raise ValueError('aggregate observation budget exhausted')
        if method=='warning':
            bounded_text(params['message'],policy.item_text_bytes)
            if params.get('threadId') is not None: turn_id(params['threadId'])
            if type(event.raw) is not bytes or len(event.raw)>profile.wire_bounds.frame_bytes:
                raise ValueError('bounded warning evidence required')
            profile.warning=event.raw
            raise ValueError('warning fences private generation')
        if method=='thread/started':
            validate_thread(params['thread'],profile.spec)
            identity=profile._thread_identity(params['thread'])
            if ((profile._candidate is not None and profile._candidate!=identity) or
                    (profile._thread is not None and profile._thread!=identity)):
                raise ValueError('contradictory staged thread')
            profile._candidate=identity
            return WireObservation(method,message,profile._thread is None)
        if method=='thread/status/changed':
            if profile._thread is None or params['threadId']!=profile._thread['id']: raise ValueError('thread status identity')
            status=params['status']; active=any(r['active'] for r in profile._intents.values())
            if not ((status=={'type':'idle'} and not active) or
                    (status=={'type':'active','activeFlags':[]} and active)):
                raise ValueError('unexpected thread activity/status')
            return WireObservation(method,message,False)
        is_turn=method in ('turn/started','turn/completed')
        if is_turn:
            server,_,_=_turn(params['turn'],policy,terminal=method=='turn/completed',bounds=profile.wire_bounds)
        else: server=params['turnId']
        record,pending=profile._correlate(params['threadId'],server,terminal=method=='turn/completed')
        if is_turn:
            for item in params['turn']['items']: profile._item(item,policy,record['purpose'],server)
        elif method in ('item/started','item/completed'):
            int64(params['startedAtMs' if method=='item/started' else 'completedAtMs'])
            profile._item(params['item'],policy,record['purpose'],server)
        elif method=='thread/tokenUsage/updated':
            usage=params['tokenUsage']; closed(usage,{'last','total'},{'modelContextWindow'})
            fields={'cachedInputTokens','inputTokens','outputTokens','reasoningOutputTokens','totalTokens'}
            for k in ('last','total'):
                closed(usage[k],fields,{'cacheWriteInputTokens'})
                for value in usage[k].values(): int64(value,nonnegative=True)
            if usage.get('modelContextWindow') is not None: int64(usage['modelContextWindow'],nonnegative=True)
            for k,v in usage['total'].items():
                if v<profile._totals.get(k,0): raise ValueError('decreasing cumulative token observation')
            profile._totals.update(usage['total'])
        elif method=='turn/plan/updated':
            plan=params['plan']
            if type(plan) is not list or len(plan)>policy.turn_items: raise ValueError('bounded plan required')
            for step in plan:
                closed(step,{'step','status'}); bounded_text(step['step'],policy.item_text_bytes)
                if step['status'] not in ('pending','inProgress','completed'): raise ValueError('plan status')
            if params.get('explanation') is not None: bounded_text(params['explanation'],policy.item_text_bytes)
        else:
            turn_id(params['itemId'])
            expected='reasoning' if '/reasoning/' in method else 'plan' if '/plan/' in method else 'agentMessage'
            identity=(server,params['itemId'])
            if identity not in profile._items:
                if len(profile._items)>=profile.bounds.max_pending_items: raise ValueError('delta item bound')
                profile._items[identity]=expected
            elif profile._items[identity]!=expected: raise ValueError('delta item mismatch')
            if 'delta' in params: bounded_text(params['delta'],policy.item_text_bytes)
            for k in ('summaryIndex','contentIndex'):
                if k in params:
                    int64(params[k],nonnegative=True)
                    if params[k]>=policy.turn_items: raise ValueError('reasoning index bound')
        terminal=parse_turn_notification(message,policy,bounds=profile.wire_bounds,purpose=record['purpose']) if method=='turn/completed' else None
        return WireObservation(method,message,pending,terminal)
