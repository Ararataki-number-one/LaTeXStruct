"""Durable, hash-bound ownership for the OCR visual and full-OCR lanes.

The page record deliberately models OCR execution, not scheduler ownership.  A
separate sidecar is therefore used to commit a visual-to-full-OCR escalation
*before* the page is enqueued.  Recovery can then resume the paid lane without
calling the visual verifier again.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import tempfile
import threading
from typing import Mapping, Sequence


OCR_LANE_ROUTE_EVENT_SCHEMA = "latexstruct-ocr-lane-route-event-v1"
OCR_LANE_ROUTE_SCHEMA = "latexstruct-ocr-lane-route-v2"
OCR_LANE_ROUTES_SCHEMA = "latexstruct-ocr-lane-routes-v2"
_PAGE_ID_RE = re.compile(r"^ocr-page-(?P<index>[0-9]{6})$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parsed_utc_timestamp(value: object) -> datetime:
    text = str(value or "")
    if not text.endswith("Z"):
        raise ValueError("OCR lane route event timestamp must be UTC")
    try:
        parsed = datetime.fromisoformat(text.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise ValueError("OCR lane route event timestamp is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError("OCR lane route event timestamp must be UTC")
    return parsed


class OcrLaneOwner(str, Enum):
    VISUAL = "VISUAL"
    FULL_OCR_QUEUED = "FULL_OCR_QUEUED"
    FULL_OCR_IN_FLIGHT = "FULL_OCR_IN_FLIGHT"
    TERMINAL_VISUAL = "TERMINAL_VISUAL"
    TERMINAL_FULL_OCR = "TERMINAL_FULL_OCR"
    TERMINAL_UNRESOLVED = "TERMINAL_UNRESOLVED"


_ALLOWED_TRANSITIONS = {
    OcrLaneOwner.VISUAL: frozenset({
        OcrLaneOwner.FULL_OCR_QUEUED,
        OcrLaneOwner.TERMINAL_VISUAL,
        OcrLaneOwner.TERMINAL_UNRESOLVED,
    }),
    OcrLaneOwner.FULL_OCR_QUEUED: frozenset({OcrLaneOwner.FULL_OCR_IN_FLIGHT}),
    OcrLaneOwner.FULL_OCR_IN_FLIGHT: frozenset({
        OcrLaneOwner.FULL_OCR_QUEUED,
        OcrLaneOwner.TERMINAL_FULL_OCR,
        OcrLaneOwner.TERMINAL_UNRESOLVED,
    }),
    OcrLaneOwner.TERMINAL_VISUAL: frozenset(),
    OcrLaneOwner.TERMINAL_FULL_OCR: frozenset(),
    OcrLaneOwner.TERMINAL_UNRESOLVED: frozenset(),
}

# These two transitions are intentionally unavailable through ``transition``.
# They exist only for narrowly named recovery operations whose callers have
# already verified the persisted page response/evidence.  Keeping them out of
# the ordinary scheduler graph prevents a queue owner or terminal owner from
# being reopened accidentally.
_ALLOWED_RECONCILIATION_TRANSITIONS = {
    OcrLaneOwner.FULL_OCR_QUEUED: frozenset({
        OcrLaneOwner.TERMINAL_FULL_OCR,
        OcrLaneOwner.TERMINAL_UNRESOLVED,
    }),
}
_ALLOWED_RETRY_TRANSITIONS = {
    OcrLaneOwner.TERMINAL_UNRESOLVED: frozenset({
        OcrLaneOwner.VISUAL,
        OcrLaneOwner.FULL_OCR_QUEUED,
    }),
}


def _history_targets(owner: OcrLaneOwner) -> frozenset[OcrLaneOwner]:
    return frozenset({
        *_ALLOWED_TRANSITIONS[owner],
        *_ALLOWED_RECONCILIATION_TRANSITIONS.get(owner, ()),
        *_ALLOWED_RETRY_TRANSITIONS.get(owner, ()),
    })

_TERMINAL_OWNERS = frozenset({
    OcrLaneOwner.TERMINAL_VISUAL,
    OcrLaneOwner.TERMINAL_FULL_OCR,
    OcrLaneOwner.TERMINAL_UNRESOLVED,
})


@dataclass(frozen=True, slots=True)
class OcrLaneRouteEvent:
    sequence: int
    owner: OcrLaneOwner
    occurred_at: str
    verifier_response_sha256: str = ""
    reason: str = ""
    previous_event_sha256: str = ""
    event_sha256: str = ""
    schema_version: str = OCR_LANE_ROUTE_EVENT_SCHEMA

    def __post_init__(self) -> None:
        if (
            not isinstance(self.sequence, int)
            or isinstance(self.sequence, bool)
            or self.sequence < 1
        ):
            raise ValueError("OCR lane route event sequence must be positive")
        owner = OcrLaneOwner(self.owner)
        occurred_at = str(self.occurred_at or "")
        _parsed_utc_timestamp(occurred_at)
        verifier = str(self.verifier_response_sha256 or "").lower()
        previous = str(self.previous_event_sha256 or "").lower()
        if verifier and _SHA256_RE.fullmatch(verifier) is None:
            raise ValueError("OCR lane route event verifier hash is invalid")
        if previous and _SHA256_RE.fullmatch(previous) is None:
            raise ValueError("OCR lane route event previous hash is invalid")
        reason = str(self.reason or "")[:500]
        body = {
            "schema_version": OCR_LANE_ROUTE_EVENT_SCHEMA,
            "sequence": self.sequence,
            "owner": owner.value,
            "occurred_at": occurred_at,
            "verifier_response_sha256": verifier,
            "reason": reason,
            "previous_event_sha256": previous,
        }
        actual = _digest(body)
        supplied = str(self.event_sha256 or "").lower()
        if supplied and not hmac.compare_digest(supplied, actual):
            raise ValueError("OCR lane route event SHA-256 mismatch")
        object.__setattr__(self, "owner", owner)
        object.__setattr__(self, "occurred_at", occurred_at)
        object.__setattr__(self, "verifier_response_sha256", verifier)
        object.__setattr__(self, "previous_event_sha256", previous)
        object.__setattr__(self, "reason", reason)
        object.__setattr__(self, "event_sha256", actual)
        object.__setattr__(self, "schema_version", OCR_LANE_ROUTE_EVENT_SCHEMA)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": OCR_LANE_ROUTE_EVENT_SCHEMA,
            "sequence": self.sequence,
            "owner": self.owner.value,
            "occurred_at": self.occurred_at,
            "verifier_response_sha256": self.verifier_response_sha256,
            "reason": self.reason,
            "previous_event_sha256": self.previous_event_sha256,
            "event_sha256": self.event_sha256,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "OcrLaneRouteEvent":
        expected = {
            "schema_version",
            "sequence",
            "owner",
            "occurred_at",
            "verifier_response_sha256",
            "reason",
            "previous_event_sha256",
            "event_sha256",
        }
        if (
            set(value) != expected
            or value.get("schema_version") != OCR_LANE_ROUTE_EVENT_SCHEMA
        ):
            raise ValueError("unsupported or malformed OCR lane route event")
        return cls(
            sequence=value.get("sequence", 0),
            owner=value.get("owner", ""),
            occurred_at=value.get("occurred_at", ""),
            verifier_response_sha256=value.get("verifier_response_sha256", ""),
            reason=value.get("reason", ""),
            previous_event_sha256=value.get("previous_event_sha256", ""),
            event_sha256=value.get("event_sha256", ""),
        )


@dataclass(frozen=True, slots=True)
class OcrLaneRoute:
    run_id: str
    page_id: str
    source_page: int
    selected_index: int
    candidate_sha256: str
    owner: OcrLaneOwner
    verifier_response_sha256: str = ""
    reason: str = ""
    previous_route_sha256: str = ""
    history: tuple[OcrLaneRouteEvent, ...] = ()
    route_sha256: str = ""
    schema_version: str = OCR_LANE_ROUTE_SCHEMA

    def __post_init__(self) -> None:
        run_id = str(self.run_id or "").strip()
        if not run_id or len(run_id) > 200 or any(ch in run_id for ch in "/\\\0"):
            raise ValueError("invalid OCR route run_id")
        match = _PAGE_ID_RE.fullmatch(str(self.page_id or ""))
        if match is None:
            raise ValueError("invalid OCR route page_id")
        if (
            not isinstance(self.selected_index, int)
            or isinstance(self.selected_index, bool)
            or self.selected_index < 1
            or int(match.group("index")) != self.selected_index
        ):
            raise ValueError("OCR route selected_index must match page_id")
        if (
            not isinstance(self.source_page, int)
            or isinstance(self.source_page, bool)
            or self.source_page < 1
        ):
            raise ValueError("OCR route source_page must be positive")
        candidate = str(self.candidate_sha256 or "").lower()
        verifier = str(self.verifier_response_sha256 or "").lower()
        previous = str(self.previous_route_sha256 or "").lower()
        if _SHA256_RE.fullmatch(candidate) is None:
            raise ValueError("OCR route candidate_sha256 must be SHA-256")
        if verifier and _SHA256_RE.fullmatch(verifier) is None:
            raise ValueError("OCR route verifier_response_sha256 must be SHA-256")
        if previous and _SHA256_RE.fullmatch(previous) is None:
            raise ValueError("OCR route previous_route_sha256 must be SHA-256")
        owner = OcrLaneOwner(self.owner)
        history = tuple(self.history)
        if not history:
            history = (OcrLaneRouteEvent(
                sequence=1,
                owner=owner,
                occurred_at=_iso_now(),
                verifier_response_sha256=verifier,
                reason=str(self.reason or "")[:500],
            ),)
        if not all(isinstance(event, OcrLaneRouteEvent) for event in history):
            raise ValueError("OCR lane route history must contain typed events")
        previous_time: datetime | None = None
        for index, event in enumerate(history, start=1):
            if event.sequence != index:
                raise ValueError("OCR lane route event sequence is not contiguous")
            occurred = _parsed_utc_timestamp(event.occurred_at)
            if previous_time is not None and occurred < previous_time:
                raise ValueError("OCR lane route event timestamps are reversed")
            previous_time = occurred
            if index == 1:
                if event.previous_event_sha256:
                    raise ValueError("first OCR lane route event has a previous hash")
            else:
                prior = history[index - 2]
                if event.previous_event_sha256 != prior.event_sha256:
                    raise ValueError("OCR lane route event hash chain is broken")
                if event.owner not in _history_targets(prior.owner):
                    raise ValueError("OCR lane route event transition is illegal")
        terminal_event = history[-1]
        if (
            terminal_event.owner is not owner
            or terminal_event.verifier_response_sha256 != verifier
            or terminal_event.reason != str(self.reason or "")[:500]
        ):
            raise ValueError("OCR lane route state differs from its event history")
        body = self._body(
            run_id=run_id,
            candidate_sha256=candidate,
            owner=owner,
            verifier_response_sha256=verifier,
            previous_route_sha256=previous,
            history=history,
        )
        actual = _digest(body)
        supplied = str(self.route_sha256 or "").lower()
        if supplied and not hmac.compare_digest(supplied, actual):
            raise ValueError("OCR route SHA-256 mismatch")
        object.__setattr__(self, "run_id", run_id)
        object.__setattr__(self, "candidate_sha256", candidate)
        object.__setattr__(self, "owner", owner)
        object.__setattr__(self, "verifier_response_sha256", verifier)
        object.__setattr__(self, "previous_route_sha256", previous)
        object.__setattr__(self, "history", history)
        object.__setattr__(self, "reason", str(self.reason or "")[:500])
        object.__setattr__(self, "route_sha256", actual)
        object.__setattr__(self, "schema_version", OCR_LANE_ROUTE_SCHEMA)

    def _body(
        self,
        *,
        run_id: str | None = None,
        candidate_sha256: str | None = None,
        owner: OcrLaneOwner | None = None,
        verifier_response_sha256: str | None = None,
        previous_route_sha256: str | None = None,
        history: Sequence[OcrLaneRouteEvent] | None = None,
    ) -> dict[str, object]:
        return {
            "schema_version": OCR_LANE_ROUTE_SCHEMA,
            "run_id": self.run_id if run_id is None else run_id,
            "page_id": self.page_id,
            "source_page": self.source_page,
            "selected_index": self.selected_index,
            "candidate_sha256": (
                self.candidate_sha256
                if candidate_sha256 is None
                else candidate_sha256
            ),
            "owner": (self.owner if owner is None else owner).value,
            "verifier_response_sha256": (
                self.verifier_response_sha256
                if verifier_response_sha256 is None
                else verifier_response_sha256
            ),
            "reason": str(self.reason or "")[:500],
            "previous_route_sha256": (
                self.previous_route_sha256
                if previous_route_sha256 is None
                else previous_route_sha256
            ),
            "history": [
                event.to_dict()
                for event in (self.history if history is None else history)
            ],
        }

    def to_dict(self) -> dict[str, object]:
        return {**self._body(), "route_sha256": self.route_sha256}

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "OcrLaneRoute":
        expected = {
            "schema_version",
            "run_id",
            "page_id",
            "source_page",
            "selected_index",
            "candidate_sha256",
            "owner",
            "verifier_response_sha256",
            "reason",
            "previous_route_sha256",
            "history",
            "route_sha256",
        }
        if set(value) != expected or value.get("schema_version") != OCR_LANE_ROUTE_SCHEMA:
            raise ValueError("unsupported or malformed OCR lane route")
        return cls(
            run_id=value.get("run_id", ""),
            page_id=value.get("page_id", ""),
            source_page=value.get("source_page", 0),
            selected_index=value.get("selected_index", 0),
            candidate_sha256=value.get("candidate_sha256", ""),
            owner=value.get("owner", ""),
            verifier_response_sha256=value.get("verifier_response_sha256", ""),
            reason=value.get("reason", ""),
            previous_route_sha256=value.get("previous_route_sha256", ""),
            history=tuple(
                OcrLaneRouteEvent.from_dict(item)
                for item in value.get("history", ())
                if isinstance(item, Mapping)
            ) if isinstance(value.get("history"), list) else (),
            route_sha256=value.get("route_sha256", ""),
        )

    def transition(
        self,
        owner: OcrLaneOwner,
        *,
        verifier_response_sha256: str | None = None,
        reason: str = "",
        occurred_at: str | None = None,
    ) -> "OcrLaneRoute":
        target = OcrLaneOwner(owner)
        if target not in _ALLOWED_TRANSITIONS[self.owner]:
            raise ValueError(
                f"illegal OCR lane transition: {self.owner.value} -> {target.value}"
            )
        verifier = (
            self.verifier_response_sha256
            if verifier_response_sha256 is None
            else verifier_response_sha256
        )
        event = OcrLaneRouteEvent(
            sequence=len(self.history) + 1,
            owner=target,
            occurred_at=occurred_at or _iso_now(),
            verifier_response_sha256=verifier,
            reason=reason,
            previous_event_sha256=self.history[-1].event_sha256,
        )
        return OcrLaneRoute(
            run_id=self.run_id,
            page_id=self.page_id,
            source_page=self.source_page,
            selected_index=self.selected_index,
            candidate_sha256=self.candidate_sha256,
            owner=target,
            verifier_response_sha256=verifier,
            reason=reason,
            previous_route_sha256=self.route_sha256,
            history=(*self.history, event),
        )

    def reconcile_terminal(
        self,
        owner: OcrLaneOwner,
        *,
        verifier_response_sha256: str | None = None,
        reason: str = "",
        occurred_at: str | None = None,
    ) -> "OcrLaneRoute":
        """Close a persisted terminal page after its evidence was verified.

        ``FULL_OCR_QUEUED`` is accepted here solely for the crash window where
        an older restart already recovered ``IN_FLIGHT`` before noticing that
        the page record and response had reached a terminal state.  Ordinary
        callers cannot take that shortcut through :meth:`transition`.
        """

        target = OcrLaneOwner(owner)
        if target not in _TERMINAL_OWNERS:
            raise ValueError("OCR lane reconciliation target must be terminal")
        if self.owner is target:
            verifier = (
                self.verifier_response_sha256
                if verifier_response_sha256 is None
                else str(verifier_response_sha256 or "").lower()
            )
            if verifier != self.verifier_response_sha256:
                raise ValueError("terminal OCR lane verifier hash mismatch")
            return self
        allowed = frozenset({
            *_ALLOWED_TRANSITIONS[self.owner],
            *_ALLOWED_RECONCILIATION_TRANSITIONS.get(self.owner, ()),
        })
        if target not in allowed:
            raise ValueError(
                f"illegal OCR lane terminal reconciliation: "
                f"{self.owner.value} -> {target.value}"
            )
        verifier = (
            self.verifier_response_sha256
            if verifier_response_sha256 is None
            else verifier_response_sha256
        )
        event = OcrLaneRouteEvent(
            sequence=len(self.history) + 1,
            owner=target,
            occurred_at=occurred_at or _iso_now(),
            verifier_response_sha256=verifier,
            reason=reason,
            previous_event_sha256=self.history[-1].event_sha256,
        )
        return OcrLaneRoute(
            run_id=self.run_id,
            page_id=self.page_id,
            source_page=self.source_page,
            selected_index=self.selected_index,
            candidate_sha256=self.candidate_sha256,
            owner=target,
            verifier_response_sha256=verifier,
            reason=reason,
            previous_route_sha256=self.route_sha256,
            history=(*self.history, event),
        )

    def retry(
        self,
        owner: OcrLaneOwner,
        *,
        reason: str,
        occurred_at: str | None = None,
    ) -> "OcrLaneRoute":
        """Append one explicit manual-retry owner without rewriting history."""

        target = OcrLaneOwner(owner)
        if target not in _ALLOWED_RETRY_TRANSITIONS.get(self.owner, ()):
            raise ValueError(
                f"illegal OCR lane retry transition: "
                f"{self.owner.value} -> {target.value}"
            )
        event = OcrLaneRouteEvent(
            sequence=len(self.history) + 1,
            owner=target,
            occurred_at=occurred_at or _iso_now(),
            verifier_response_sha256=self.verifier_response_sha256,
            reason=reason,
            previous_event_sha256=self.history[-1].event_sha256,
        )
        return OcrLaneRoute(
            run_id=self.run_id,
            page_id=self.page_id,
            source_page=self.source_page,
            selected_index=self.selected_index,
            candidate_sha256=self.candidate_sha256,
            owner=target,
            verifier_response_sha256=self.verifier_response_sha256,
            reason=reason,
            previous_route_sha256=self.route_sha256,
            history=(*self.history, event),
        )


class OcrLaneRouteStore:
    """Atomic page-local route sidecars under one already-validated run dir."""

    def __init__(self, run_dir: Path) -> None:
        self.run_dir = Path(run_dir).resolve()
        self.routes_dir = self.run_dir / "routes"
        self._lock = threading.RLock()

    def _path(self, page_id: str) -> Path:
        if _PAGE_ID_RE.fullmatch(str(page_id or "")) is None:
            raise ValueError("invalid OCR route page_id")
        return self.routes_dir / f"{page_id}.json"

    @staticmethod
    def _atomic_write(path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        handle, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        try:
            with os.fdopen(handle, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    def load(self, page_id: str) -> OcrLaneRoute | None:
        with self._lock:
            path = self._path(page_id)
            if not path.exists():
                return None
            if path.is_symlink() or not path.is_file():
                raise ValueError("OCR lane route cannot be a link or non-file")
            data = path.read_bytes()
            if len(data) > 32_768:
                raise ValueError("OCR lane route exceeds size bound")
            try:
                value = json.loads(data.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError("OCR lane route is corrupt") from exc
            if not isinstance(value, dict):
                raise ValueError("OCR lane route must be an object")
            return OcrLaneRoute.from_dict(value)

    def create(self, route: OcrLaneRoute) -> OcrLaneRoute:
        with self._lock:
            path = self._path(route.page_id)
            existing = self.load(route.page_id)
            if existing is not None:
                if existing == route:
                    return existing
                raise ValueError("OCR lane route already exists")
            self._atomic_write(path, _canonical_json(route.to_dict()))
            return self.load(route.page_id)  # type: ignore[return-value]

    def transition(
        self,
        page_id: str,
        owner: OcrLaneOwner,
        *,
        verifier_response_sha256: str | None = None,
        reason: str = "",
    ) -> OcrLaneRoute:
        with self._lock:
            current = self.load(page_id)
            if current is None:
                raise ValueError("OCR lane route is missing")
            updated = current.transition(
                owner,
                verifier_response_sha256=verifier_response_sha256,
                reason=reason,
            )
            self._atomic_write(self._path(page_id), _canonical_json(updated.to_dict()))
            return self.load(page_id)  # type: ignore[return-value]

    def reconcile_terminal(
        self,
        page_id: str,
        owner: OcrLaneOwner,
        *,
        verifier_response_sha256: str | None = None,
        reason: str = "",
    ) -> OcrLaneRoute:
        """Atomically close a route after external terminal-evidence checks."""

        with self._lock:
            current = self.load(page_id)
            if current is None:
                raise ValueError("OCR lane route is missing")
            updated = current.reconcile_terminal(
                owner,
                verifier_response_sha256=verifier_response_sha256,
                reason=reason,
            )
            if updated is current:
                return current
            self._atomic_write(self._path(page_id), _canonical_json(updated.to_dict()))
            return self.load(page_id)  # type: ignore[return-value]

    def retry(
        self,
        page_id: str,
        owner: OcrLaneOwner,
        *,
        reason: str,
    ) -> OcrLaneRoute:
        """Atomically append an explicit retry transition to the route chain."""

        with self._lock:
            current = self.load(page_id)
            if current is None:
                raise ValueError("OCR lane route is missing")
            updated = current.retry(owner, reason=reason)
            self._atomic_write(self._path(page_id), _canonical_json(updated.to_dict()))
            return self.load(page_id)  # type: ignore[return-value]

    def recover(self, page_id: str) -> OcrLaneRoute | None:
        with self._lock:
            current = self.load(page_id)
            if current is not None and current.owner is OcrLaneOwner.FULL_OCR_IN_FLIGHT:
                return self.transition(
                    page_id,
                    OcrLaneOwner.FULL_OCR_QUEUED,
                    reason="recovered interrupted full OCR lane",
                )
            return current

    def list(self) -> tuple[OcrLaneRoute, ...]:
        with self._lock:
            if not self.routes_dir.exists():
                return ()
            result = []
            for path in sorted(self.routes_dir.glob("ocr-page-*.json")):
                route = self.load(path.stem)
                if route is not None:
                    result.append(route)
            result.sort(key=lambda item: item.selected_index)
            return tuple(result)


def build_lane_routes_artifact(
    *,
    run_id: str,
    selected_pages: Sequence[int],
    routes: Sequence[OcrLaneRoute],
) -> bytes:
    """Freeze one terminal, ordered route for every selected source page."""

    pages = tuple(int(page) for page in selected_pages)
    if (
        not pages
        or any(page < 1 for page in pages)
        or len(set(pages)) != len(pages)
    ):
        raise ValueError("selected OCR route pages must be unique and positive")
    ordered = tuple(sorted(routes, key=lambda item: item.selected_index))
    if len(ordered) != len(pages):
        raise ValueError("OCR lane routes do not cover every selected page")
    counts = {owner.value: 0 for owner in sorted(_TERMINAL_OWNERS, key=lambda item: item.value)}
    for selected_index, (source_page, route) in enumerate(
        zip(pages, ordered, strict=True),
        start=1,
    ):
        if (
            route.run_id != str(run_id)
            or route.selected_index != selected_index
            or route.page_id != f"ocr-page-{selected_index:06d}"
            or route.source_page != source_page
            or route.owner not in _TERMINAL_OWNERS
        ):
            raise ValueError("OCR lane route identity or terminal ownership is incomplete")
        if (
            route.owner is OcrLaneOwner.TERMINAL_VISUAL
            and not route.verifier_response_sha256
        ):
            raise ValueError("terminal visual route lacks verifier response evidence")
        counts[route.owner.value] += 1
    return _canonical_json({
        "schema_version": OCR_LANE_ROUTES_SCHEMA,
        "run_id": str(run_id),
        "selected_pages": list(pages),
        "terminal_counts": counts,
        "event_count": sum(len(route.history) for route in ordered),
        "routes": [route.to_dict() for route in ordered],
    })


def parse_lane_routes_artifact(
    data: bytes,
    *,
    expected_run_id: str,
    expected_selected_pages: Sequence[int],
) -> tuple[OcrLaneRoute, ...]:
    """Recompute and validate a frozen terminal lane-route artifact."""

    try:
        value = json.loads(bytes(data).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("OCR lane routes artifact is invalid JSON") from exc
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "run_id",
        "selected_pages",
        "terminal_counts",
        "event_count",
        "routes",
    }:
        raise ValueError("OCR lane routes artifact is malformed")
    if value.get("schema_version") != OCR_LANE_ROUTES_SCHEMA:
        raise ValueError("unsupported OCR lane routes artifact")
    if bytes(data) != _canonical_json(value):
        raise ValueError("OCR lane routes artifact is not canonical JSON")
    raw_routes = value.get("routes")
    if not isinstance(raw_routes, list) or any(
        not isinstance(item, dict) for item in raw_routes
    ):
        raise ValueError("OCR lane routes must be an array of objects")
    routes = tuple(OcrLaneRoute.from_dict(item) for item in raw_routes)
    if value.get("event_count") != sum(len(route.history) for route in routes):
        raise ValueError("OCR lane route event count is stale")
    canonical = build_lane_routes_artifact(
        run_id=str(expected_run_id),
        selected_pages=tuple(expected_selected_pages),
        routes=routes,
    )
    if canonical != bytes(data):
        raise ValueError("OCR lane routes differ from the expected run or pages")
    return routes
