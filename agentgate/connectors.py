from abc import ABC, abstractmethod
import secrets
from .secrets_guard import lint_tool_definition


class ToolConnector(ABC):
    @abstractmethod
    def list_tools(self): ...

    @abstractmethod
    def invoke(self, tool, args, assertion): ...


class FakeConnector(ToolConnector):
    """In-process demo connector.

    Gateway and connector remain in one process, but connector assertions use a
    distinct audience key ring, are bound to canonical tool arguments, and are
    accepted only once. A production connector needs independently deployed key
    custody and asymmetric verification.
    """

    def __init__(self, token_service):
        self._tokens = token_service
        self._downstream_api_key = "fake-not-a-secret"
        self._tools = [
            {"name": "crm.lookup_account", "description": "Look up a made-up account", "inputSchema": {"type": "object"}},
            {"name": "payments.refund", "description": "Queue a fake refund", "inputSchema": {"type": "object"}},
            {"name": "files.read", "description": "Read a fake report", "inputSchema": {"type": "object"}},
            {"name": "email.send", "description": "Demonstrates default denial", "inputSchema": {"type": "object"}},
        ]
        for item in self._tools:
            lint_tool_definition(item)

    def list_tools(self):
        return [dict(item) for item in self._tools]

    def invoke(self, tool, args, assertion):
        self._tokens.verify_connector_assertion(assertion, tool, args)
        if tool == "crm.lookup_account":
            return {"account_id": "ACME-0001", "tier": "gold", "open_tickets": 2}
        if tool == "payments.refund":
            return {"refund_id": "rf_" + secrets.token_hex(4), "status": "queued"}
        if tool == "files.read":
            return {"content": "Q3 summary (sample): all figures are made up."}
        if tool == "email.send":
            return {"status": "not-sent"}
        raise ValueError("unknown tool")
