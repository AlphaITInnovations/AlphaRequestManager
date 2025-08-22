# File: alpharequestmanager/manager.py
from .logger import logger
from .database import insert_ticket, list_all_tickets, list_tickets_by_owner, init_db, update_ticket, update_ticket_metadata, get_ticket_metadata
from .models import Ticket, RequestStatus


class RequestManager:
    def __init__(self):
        init_db()



    def submit_ticket(self,
                      title: str,
                      description: str,
                      owner_id: str,
                      owner_name: str,
                      owner_info: str) -> int:
        ticket_id = insert_ticket(title, description, owner_id, owner_name, owner_info)

        return ticket_id

    def list_all_tickets(self) -> list[Ticket]:
        return list_all_tickets()

    def list_tickets(self, owner_id: str) -> list[Ticket]:
        return list_tickets_by_owner(owner_id)

    def update_status(self, ticket_id: int, status: RequestStatus):
        logger.info(f"Updating ticket status for ticket id {ticket_id}")
        update_ticket(ticket_id, status=status)

    def set_comment(self, ticket_id: int, text: str):
        update_ticket(ticket_id, comment=text)

    def set_ninja_metadata(self, ticket_id: int, ninja_ticket_id: int):
        """
        Verknüpft ein lokales Ticket mit einem NinjaOne-Ticket.
        Speichert zusätzlich den Sync-Timestamp.
        """
        logger.info(f"Mapping local ticket {ticket_id} -> Ninja ticket {ninja_ticket_id}")
        update_ticket_metadata(ticket_id, ninja_ticket_id=ninja_ticket_id)

    # 🆕 NinjaOne-Metadaten auslesen
    def get_ninja_metadata(self, ticket_id: int) -> dict | None:
        """
        Liefert gespeicherte NinjaOne-Metadaten für ein Ticket zurück.
        Beispiel: {"ninja_ticket_id": 5980, "synced_at": "..."}
        """
        meta = get_ticket_metadata(ticket_id)
        logger.debug(f"Loaded Ninja metadata for ticket {ticket_id}: {meta}")
        return meta
