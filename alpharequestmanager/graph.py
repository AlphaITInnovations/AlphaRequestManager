import httpx
from typing import List
from  alpharequestmanager.config import TICKET_MAIL

GRAPH_API_ME = "https://graph.microsoft.com/v1.0/me"
GRAPH_API_GROUPS = "https://graph.microsoft.com/v1.0/me/memberOf"
GRAPH_API_SENDMAIL = "https://graph.microsoft.com/v1.0/me/sendMail"

async def get_user_profile(access_token: str) -> dict:
    headers = {
        "Authorization": f"Bearer {access_token}"
    }

    async with httpx.AsyncClient() as client:
        # User Details mit erweiterten Feldern
        profile_url = (
            GRAPH_API_ME +
            "?$select=displayName,jobTitle,mobilePhone,businessPhones,companyName,streetAddress,officeLocation,city,postalCode"
        )
        r = await client.get(profile_url, headers=headers)
        r.raise_for_status()
        me = r.json()

        # Gruppenmitgliedschaften
        groups_response = await client.get(GRAPH_API_GROUPS, headers=headers)
        groups_response.raise_for_status()
        groups_data = groups_response.json()

    group_names: List[str] = [
        g.get("displayName") for g in groups_data.get("value", [])
        if g.get("@odata.type") == "#microsoft.graph.group"
    ]

    return {
        "phone": ", ".join(me.get("businessPhones", [])) or None,
        "mobile": me.get("mobilePhone"),
        "address": {
            "street": me.get("streetAddress"),
            "zip": me.get("postalCode"),
            "city": me.get("city") or me.get("officeLocation")
        },
        "company": me.get("companyName"),
        "position": me.get("jobTitle"),
        "group_names": group_names
    }


async def send_mail(
    access_token: str,
    subject: str,
    content: str,
    save_to_sent_items: bool = True,
) -> None:
    """Sendet eine E-Mail im Kontext des aktuellen Benutzers."""
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    body = {
        "message": {
            "subject": subject,
            "body": {"contentType": "HTML", "content": content},
            "toRecipients": [
                {"emailAddress": {"address": TICKET_MAIL}}
            ],
        },
        "saveToSentItems": str(save_to_sent_items).lower(),
    }

    async with httpx.AsyncClient() as client:
        resp = await client.post(GRAPH_API_SENDMAIL, headers=headers, json=body)
        resp.raise_for_status()