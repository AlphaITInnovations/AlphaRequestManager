import time
from datetime import datetime
from alpharequestmanager import database, ninja_api
from alpharequestmanager.database import update_ticket
from alpharequestmanager.ninja_api import get_ticket
from alpharequestmanager.logger import logger
from alpharequestmanager.models import RequestStatus
from alpharequestmanager.config import cfg as config

def poll_ninja_changes():
    """
    Pollt alle Tickets mit 'ninja_ticket_id' und synchronisiert Status-Änderungen zurück ins Self-Service-Portal.
    """
    tickets = database.list_pending_tickets()
    for t in tickets:

        ninja_ticket = get_ticket(t.ninja_ticket_id)
        status_id = ninja_ticket.get("status", {}).get("statusId")

        if status_id == 5000:
            comment = ninja_api.get_alpha_request_comment(ninja_ticket)
            database.update_ticket(int(t.id), comment=comment)
            status = ninja_api.is_alpha_request_approved(t.ninja_ticket_id)
            if status:
                logger.info("Ticket has been approved: " + str(t.ninja_ticket_id))
                database.update_ticket(int(t.id), status="approved")
            elif not status:
                logger.info("Ticket has been rejected: " + str(t.ninja_ticket_id))
                database.update_ticket(int(t.id), status="rejected")


def start_polling():
    #logger.info("Starte Ninja-Sync Polling...")
    while True:
        poll_ninja_changes()
        time.sleep(config.NINJA_POLL_INTERVAL)
