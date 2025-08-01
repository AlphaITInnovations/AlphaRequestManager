# File: alpharequestmanager/models.py
from dataclasses import dataclass
from enum import Enum
from datetime import datetime

class RequestStatus(str, Enum):
    pending  = "pending"
    approved = "approved"
    rejected = "rejected"

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
            owner_info=row["owner_info"]
        )