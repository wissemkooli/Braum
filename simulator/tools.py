"""Tool implementations for the three synthetic domains.

Each tool returns labelled fields. The labels are the environment's honest
account of where content came from -- a third-party enrichment feed is
UNTRUSTED_EXTERNAL whether or not an attacker has written anything into it.
"""

from __future__ import annotations

from typing import Callable, Dict

from .env import Environment, Field, ToolResult

REGISTRY: Dict[str, Callable[[Environment, dict], ToolResult]] = {}


def tool(name: str):
    def deco(fn):
        REGISTRY[name] = fn
        return fn
    return deco


def _missing(kind: str, key: str) -> ToolResult:
    return ToolResult(ok=False, error=f"{kind} {key!r} not found")


# ------------------------------------------------------------------ enterprise
@tool("document_read")
def document_read(env: Environment, args: dict) -> ToolResult:
    key = str(args.get("document_id", ""))
    rec = env.record("documents", key)
    if not rec:
        return _missing("document", key)
    env.read_log.append(f"documents/{key}")
    return ToolResult(
        data={"document_id": key, "title": rec.get("title", "")},
        fields=[env.field_from_record("document_read", "documents", key, "body", rec)],
    )


@tool("email_read")
def email_read(env: Environment, args: dict) -> ToolResult:
    key = str(args.get("email_id", ""))
    rec = env.record("emails", key)
    if not rec:
        return _missing("email", key)
    env.read_log.append(f"emails/{key}")
    return ToolResult(
        data={"email_id": key, "subject": rec.get("subject", ""), "from": rec.get("from", "")},
        fields=[env.field_from_record("email_read", "emails", key, "body", rec)],
    )


@tool("wiki_read")
def wiki_read(env: Environment, args: dict) -> ToolResult:
    key = str(args.get("page_id", ""))
    rec = env.record("wiki", key)
    if not rec:
        return _missing("wiki page", key)
    env.read_log.append(f"wiki/{key}")
    return ToolResult(
        data={"page_id": key, "title": rec.get("title", "")},
        fields=[env.field_from_record("wiki_read", "wiki", key, "body", rec)],
    )


@tool("email_draft")
def email_draft(env: Environment, args: dict) -> ToolResult:
    key = env.next_id("DRAFT")
    env.put("drafts", key, {
        "subject": args.get("subject", ""), "body": args.get("body", ""), "to": args.get("to", "")})
    return ToolResult(data={"draft_id": key}, effect="email_draft")


@tool("email_send")
def email_send(env: Environment, args: dict) -> ToolResult:
    key = env.next_id("SENT")
    env.put("outbound", key, {
        "to": args.get("to", ""), "subject": args.get("subject", ""), "body": args.get("body", "")})
    return ToolResult(data={"message_id": key}, effect="email_send")


@tool("ticket_update")
def ticket_update(env: Environment, args: dict) -> ToolResult:
    key = str(args.get("ticket_id", ""))
    rec = env.record("tickets", key)
    if not rec:
        return _missing("ticket", key)
    if args.get("comment"):
        rec.setdefault("comments", []).append(str(args["comment"]))
    effect = "ticket_update"
    status = str(args.get("status", "")).strip().lower()
    if status:
        rec["status"] = status
        effect = {"closed": "ticket_close", "reopened": "ticket_reopen"}.get(status, "ticket_update")
    for extra in ("assignee", "priority"):
        if args.get(extra):
            rec[extra] = args[extra]
    return ToolResult(data={"ticket_id": key, "status": rec.get("status")}, effect=effect)


@tool("ticket_close")
def ticket_close(env: Environment, args: dict) -> ToolResult:
    key = str(args.get("ticket_id", ""))
    rec = env.record("tickets", key)
    if not rec:
        return _missing("ticket", key)
    rec["status"] = "closed"
    rec["resolution"] = args.get("resolution", "")
    return ToolResult(data={"ticket_id": key}, effect="ticket_close")


@tool("memory_write")
def memory_write(env: Environment, args: dict) -> ToolResult:
    key = str(args.get("key", env.next_id("MEM")))
    env.put("memory", key, {
        "value": args.get("value", ""),
        # Written after reading untrusted content, so it is untrusted when recalled.
        "trust": env.collections.get("_memory_trust", {}).get("level", "UNTRUSTED_INTERNAL"),
        "sensitivity": "INTERNAL",
    })
    return ToolResult(data={"key": key}, effect="memory_write")


@tool("memory_read")
def memory_read(env: Environment, args: dict) -> ToolResult:
    key = str(args.get("key", ""))
    rec = env.record("memory", key)
    if not rec:
        return _missing("memory entry", key)
    env.read_log.append(f"memory/{key}")
    return ToolResult(
        data={"key": key},
        fields=[Field("value", str(rec.get("value", "")), rec.get("trust", "UNTRUSTED_INTERNAL"),
                      rec.get("sensitivity", "INTERNAL"), f"memory/{key}/value")],
    )


# --------------------------------------------------------------------- finance
@tool("account_summary")
def account_summary(env: Environment, args: dict) -> ToolResult:
    key = str(args.get("customer_id", ""))
    rec = env.record("customers", key)
    if not rec:
        return _missing("customer", key)
    env.read_log.append(f"customers/{key}")
    summary = (f"Customer {rec.get('name')} ({key}) is {rec.get('status')}. "
               f"Segment {rec.get('segment')}, opened {rec.get('opened')}.")
    return ToolResult(
        data={"customer_id": key, "status": rec.get("status")},
        fields=[
            Field("summary", summary, "TRUSTED_INTERNAL", rec.get("sensitivity", "CONFIDENTIAL"),
                  f"customers/{key}/summary"),
            # The advisory block is a third-party feed rendered inside our tool output.
            env.field_from_record("account_summary", "customers", key, "advisory", rec,
                                  trust="UNTRUSTED_EXTERNAL", sensitivity="INTERNAL"),
        ],
    )


@tool("payment_prepare")
def payment_prepare(env: Environment, args: dict) -> ToolResult:
    key = str(args.get("payment_id", ""))
    rec = env.record("payments", key)
    if not rec:
        return _missing("payment", key)
    rec["state"] = "prepared"
    for extra in ("amount", "beneficiary", "memo"):
        if args.get(extra):
            rec[extra] = args[extra]
    return ToolResult(data={"payment_id": key, "state": "prepared"}, effect="payment_prepare")


@tool("payment_confirm")
def payment_confirm(env: Environment, args: dict) -> ToolResult:
    key = str(args.get("payment_id", ""))
    rec = env.record("payments", key)
    if not rec:
        return _missing("payment", key)
    rec["state"] = "confirmed"
    return ToolResult(data={"payment_id": key, "state": "confirmed"}, effect="payment_confirm")


@tool("payment_execute")
def payment_execute(env: Environment, args: dict) -> ToolResult:
    key = str(args.get("payment_id", ""))
    rec = env.record("payments", key)
    if not rec:
        return _missing("payment", key)
    rec["state"] = "executed"
    return ToolResult(data={"payment_id": key, "state": "executed",
                            "amount_eur": rec.get("amount_eur")}, effect="payment_execute")


@tool("case_note_create")
def case_note_create(env: Environment, args: dict) -> ToolResult:
    key = env.next_id("CASE")
    env.put("case_notes", key, {"customer_id": args.get("customer_id", ""), "note": args.get("note", "")})
    return ToolResult(data={"case_note_id": key}, effect="case_note_create")


@tool("customer_notify")
def customer_notify(env: Environment, args: dict) -> ToolResult:
    key = env.next_id("MSG")
    env.put("outbound", key, {"to": args.get("customer_id", ""), "channel": args.get("channel", "email"),
                              "body": args.get("message", "")})
    return ToolResult(data={"message_id": key}, effect="customer_notify")


# ------------------------------------------------------------------------- soc
@tool("alert_read")
def alert_read(env: Environment, args: dict) -> ToolResult:
    key = str(args.get("alert_id", ""))
    rec = env.record("alerts", key)
    if not rec:
        return _missing("alert", key)
    env.read_log.append(f"alerts/{key}")
    return ToolResult(
        data={"alert_id": key, "severity": rec.get("severity"), "title": rec.get("title")},
        fields=[
            env.field_from_record("alert_read", "alerts", key, "summary", rec,
                                  trust="TRUSTED_INTERNAL"),
            # Enrichment is a third-party intel feed pasted into our own tool result.
            env.field_from_record("alert_read", "alerts", key, "enrichment", rec,
                                  trust="UNTRUSTED_EXTERNAL"),
        ],
    )


@tool("intel_lookup")
def intel_lookup(env: Environment, args: dict) -> ToolResult:
    needle = str(args.get("indicator", ""))
    for key, rec in env.collections.get("intel", {}).items():
        if needle and needle in (rec.get("indicator", ""), key):
            env.read_log.append(f"intel/{key}")
            return ToolResult(
                data={"intel_id": key},
                fields=[env.field_from_record("intel_lookup", "intel", key, "body", rec)],
            )
    return _missing("indicator", needle)


@tool("incident_create")
def incident_create(env: Environment, args: dict) -> ToolResult:
    key = env.next_id("INC")
    env.put("incidents", key, {"title": args.get("title", ""), "team": args.get("team", ""),
                               "severity": args.get("severity", ""), "status": "open", "comments": []})
    return ToolResult(data={"incident_id": key}, effect="incident_create")


@tool("incident_comment")
def incident_comment(env: Environment, args: dict) -> ToolResult:
    key = str(args.get("incident_id", ""))
    rec = env.record("incidents", key)
    if not rec:
        return _missing("incident", key)
    rec.setdefault("comments", []).append(str(args.get("comment", "")))
    return ToolResult(data={"incident_id": key}, effect="incident_comment")


@tool("incident_close")
def incident_close(env: Environment, args: dict) -> ToolResult:
    key = str(args.get("incident_id", ""))
    rec = env.record("incidents", key)
    if not rec:
        return _missing("incident", key)
    rec["status"] = "closed"
    rec["resolution"] = args.get("resolution", "")
    return ToolResult(data={"incident_id": key}, effect="incident_close")


@tool("credential_reset")
def credential_reset(env: Environment, args: dict) -> ToolResult:
    key = str(args.get("user_id", ""))
    rec = env.record("users", key)
    if not rec:
        return _missing("user", key)
    rec["credentials_reset"] = True
    return ToolResult(data={"user_id": key}, effect="credential_reset")


@tool("host_isolate")
def host_isolate(env: Environment, args: dict) -> ToolResult:
    key = str(args.get("host_id", ""))
    rec = env.record("hosts", key)
    if not rec:
        return _missing("host", key)
    rec["isolated"] = True
    return ToolResult(data={"host_id": key}, effect="host_isolate")


@tool("monitoring_disable")
def monitoring_disable(env: Environment, args: dict) -> ToolResult:
    key = str(args.get("host_id", ""))
    rec = env.record("hosts", key)
    if not rec:
        return _missing("host", key)
    rec["monitoring"] = "disabled"
    return ToolResult(data={"host_id": key, "duration": args.get("duration", "")},
                      effect="monitoring_disable")


def invoke(env: Environment, tool_name: str, args: dict) -> ToolResult:
    if env.allowed_tools and tool_name not in env.allowed_tools:
        return ToolResult(ok=False, error=f"tool {tool_name!r} is not enabled for this task")
    fn = REGISTRY.get(tool_name)
    if fn is None:
        return ToolResult(ok=False, error=f"unknown tool {tool_name!r}")
    return fn(env, args)
