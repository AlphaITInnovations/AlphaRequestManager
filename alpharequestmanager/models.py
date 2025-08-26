# File: alpharequestmanager/models.py
import json
from dataclasses import dataclass
from enum import Enum
from datetime import datetime

class RequestStatus(str, Enum):
    pending  = "pending"
    approved = "approved"
    rejected = "rejected"

class TicketType(str, Enum):
    hardware = "Hardwarebestellung"
    niederlassungAnmeldung = "Niederlassung anmelden"
    niederlassungAbmeldung = "Niederlassung schließen"
    niederlassungUmzug = "Niederlassung umzug"
    zugangBeantragen = "EDV-Zugang beantragen"
    zugangSperren = "EDV-Zugang sperren"


@dataclass
class Ticket:
    id: str
    title: str
    description: str
    owner_id: str
    owner_name: str
    comment: str
    status: RequestStatus
    created_at: datetime
    owner_info: str
    ninja_metadata: str


    @classmethod
    def from_row(cls, row):
        return cls(
            id=row["id"],
            title=row["title"],
            description=row["description"],
            owner_id=row["owner_id"],
            owner_name=row["owner_name"],
            comment=row["comment"] or "",
            status=RequestStatus(row["status"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            owner_info=row["owner_info"],
            ninja_metadata=row["ninja_metadata"] if "ninja_metadata" in row.keys() else None

        )

    # ✅ Neues Property: parsed Metadata
    @property
    def metadata(self) -> dict:
        if not self.ninja_metadata:
            return {}
        try:
            return json.loads(self.ninja_metadata)
        except Exception:
            return {}

    @property
    def ninja_ticket_id(self) -> int | None:
        return self.metadata.get("ninja_ticket_id")

    @property
    def synced_at(self) -> datetime | None:
        ts = self.metadata.get("synced_at")
        if ts:
            try:
                return datetime.fromisoformat(ts)
            except Exception:
                return None
        return None