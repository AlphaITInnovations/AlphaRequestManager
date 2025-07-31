# File: alpharequestmanager/manager.py
from .logger import logger
from .database import insert_ticket, list_all_tickets, list_tickets_by_owner, init_db, update_ticket
from .models import Ticket, RequestStatus


class RequestManager:
    def __init__(self):
        init_db()



    def submit_ticket(self,
                      title: str,
                      description: str,
                      owner_id: str,
                      owner_name: str) -> Ticket:
        # 1) Insert und ID holen
        ticket_id = insert_ticket(title, description, owner_id, owner_name)
        # 2) komplettes Ticket laden
        all_tix = list_all_tickets()
        # 3) jenes raussuchen, das wir gerade angelegt haben
        return next(t for t in all_tix if t.id == ticket_id)

    def list_all_tickets(self) -> list[Ticket]:
        return list_all_tickets()

    def list_tickets(self, owner_id: str) -> list[Ticket]:
        return list_tickets_by_owner(owner_id)

    def update_status(self, ticket_id: int, status: RequestStatus):
        logger.info(f"Updating ticket status for ticket id {ticket_id}")
        update_ticket(ticket_id, status=status)

    def set_comment(self, ticket_id: int, text: str):
        update_ticket(ticket_id, comment=text)