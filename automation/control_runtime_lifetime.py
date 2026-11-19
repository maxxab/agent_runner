"""One-way resource transition from original setup to the actual Store lifetime.

No origin capture, deadline mutation, Store creation or independent authority.
The retained setup clock remains immutable evidence after successful binding.
"""
from . import control_runtime_clock as clock
from . import control_store as cs
from .control_runtime_seal import _Clock


class ResourceClock:
    def __init__(self, anchor):
        self.setup = _Clock(anchor)
        self.anchor = anchor
        self._attempted = self._fenced = False
        self._guard = self._actual = None

    def bind(self, guard):
        from .control_runtime_readiness import ReadyGuard
        try:
            if self._attempted or self._fenced:
                raise ValueError('resource lifetime binding already consumed or fenced')
            self._attempted = True
            self.setup.check()
            if (type(guard) is not ReadyGuard or guard._synthetic or not guard.ready or
                    guard._closed or guard._owner != self.setup.owner or guard.anchor != self.anchor or
                    type(guard._store_anchor) is not cs.RuntimeClockAnchor):
                raise ValueError('original protected Store readiness required')
            guard._check(guard._setup_end)
            clock.check(guard._store_anchor, positive=True)
            self.setup.check()
            self._last_boot,self._wall = self.setup.last_boot,self.setup.wall
            self._guard, self._actual = guard, guard._store_anchor
            self.check()
        except BaseException:
            self._fenced = True
            raise

    def check(self):
        try:
            if self._fenced:
                raise ValueError('resource lifetime fenced')
            if self._guard is None:
                self.setup.check()
                return
            guard = self._guard
            if (not guard.ready or guard._closed or guard._owner != self.setup.owner or guard.anchor != self.anchor or
                    guard._store_anchor != self._actual):
                raise ValueError('original Store lifetime binding lost')
            now,wall=guard._check_store_lifetime(self._actual)
            if now<self._last_boot or wall<self._wall:
                raise ValueError('resource clock moved backwards across binding')
            self._last_boot,self._wall=now,wall
        except BaseException:
            self._fenced = True
            raise
