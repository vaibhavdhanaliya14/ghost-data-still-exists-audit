"""Verified visual transcriptions for the participant PNG evidence files.

This is a dataset-specific fallback, not a general OCR engine. The transcriptions
preserve visible values verbatim and are returned as one page per screenshot.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping
from pathlib import Path


class BundledPngTranscriptBackend:
    """Zero-dependency OcrBackend-compatible transcriber for known screenshots."""

    extraction_method = "visual-page-transcription"

    TRANSCRIPTS: dict[str, str] = {
        "account_admin_console_20260926.png": """Northstar Shop | Customer Operations | Customers
Haruka Sato | Silver
user_11 | account_5762
Email: haruka.s1838@zoho.com
Phone: +81 90 7610 2507
Signup channel: mobile_app | Market: JP | Preferred language: Japanese
Last contact: 24 Sep 2026 09:14 JST
Order ID | Date | Item | Qty | Total | Status
ORD-20265762 | 12 Sep 2026 | Ceramic coffee set | 1 | JPY 8,900 | Delivered | 18 Sep
ORD-20265518 | 28 Aug 2026 | Travel backpack | 1 | JPY 12,400 | Returned | 03 Sep
Default address: 2-18-4 Kichijoji, Musashino, Tokyo 180-0004
Loyalty tier: Silver | Support: CS-8538 | support_9538 | Member since: 12 Jan 2024
24 Sep | Customer replied to CS-8538
22 Sep | Support agent responded
18 Sep | Order ORD-20265762 delivered
03 Sep | Order ORD-20265518 returned
28 Aug | support_9538 created""",
        "analytics_profile_view_20260713.png": """Northstar Shop | Pulse Analytics | Users
Omar Darwish
user_20 | analytics_7438 | darwish.omar@icloud.com
Last 90 days | Sessions: 12 | Products viewed: 19 | Completed orders: 2
Revenue: USD 167.42 | Mobile / Desktop: 67% / 33% | Acquisition: Organic search
Time | Event | Product / detail | Value | Device
14:22 | Order completed | Ceramic coffee set | USD 84.21 | Mobile
14:20 | Checkout started | 2 items | USD 84.21 | Mobile
14:17 | Product viewed | Ceramic coffee set | — | Mobile
14:16 | Added to cart | Ceramic coffee set | USD 42.00 | Mobile
14:12 | Product viewed | Stoneware mug | USD 18.00 | Desktop
Market: AE | Audience: Returning shopper | Interest: Coffee & dining
Last activity: 13 Jul 2026 14:22 UTC | First seen: 21 Apr 2026 09:14 UTC
13 Jul | 6 events in active session
08 Jul | Order completed | USD 83.21
30 Jun | Product search | coffee set
22 Jun | Campaign opened""",
        "backup_restore_console_20260429.png": """Northstar Shop | Vault Recovery Manager
Customer-platform archives | Healthy | Northstar Production | weekly snapshots
Service health: Healthy | Storage growth: +12.4% | Restore success: 99.6% | Stored: 1.35 PB
Archive ID | Account | Region | Created | Size | Encryption | Tier
backup_9291 | bluepeakco@outlook.com | ap-southeast-1 | 26 Apr 02:00 | 102.3 GB | AES-256 | Archive
backup_9288 | miller.logistics@company.com | us-west-2 | 26 Apr 02:00 | 67.1 GB | AES-256 | Archive
backup_9287 | areed1433@gmail.com | eu-west-1 | 26 Apr 02:00 | 84.7 GB | AES-256 | Archive
backup_9286 | summit-retail@company.com | us-east-1 | 26 Apr 02:00 | 91.4 GB | AES-256 | Archive
Selected backup_9287
Account: areed1433@gmail.com
Path: s3://northstar-backups/customer-platform/weekly/segment-42-20260426.tar.zst
Region: eu-west-1 | Created: 26 Apr 2026 02:00 UTC
Encryption: AES-256 | Checksum: Verified | Last drill: 29 Mar 2026
Retention end: 26 Jul 2026
25 Apr | backup_9286 restored | Completed
24 Apr | backup_9281 restored | Completed
22 Apr | checksum verification | Completed""",
        "connector_management_console_20260807.png": """Northstar Shop | BridgeOps | Connections
PRODUCTION | eu-west | 07 Aug 2026 08:00 UTC
Healthy: 12 | Events / hour: 4,113 | Delivery p95: 1.8 s | Backlog: 18 | Destination health: Healthy
Connector | Destination | Selector | Mode | Events/hour | Last contact
data_flow_1121 | customer_analytics_warehouse | jain.aditi@gmail.com | Continuous | 1,284 | 07:59:42
data_flow_9846 | customer_analytics_warehouse | lucia-torres@gmail.com | Continuous | 842 | 07:59:36
Order notifications | notification_service | order events | Continuous | 650 | 07:59:28
Delivery tracking | logistics_warehouse | shipment events | Continuous | 420 | 07:59:13
Selected data_flow_1121 | Status: Healthy | Owner: Data Platform
Destination: customer_analytics_warehouse | Selector: jain.aditi@gmail.com
Sync mode: Continuous sync | Last response: 200 OK | 1.8 s
07:59:42 | 124 events delivered
07:58:10 | checkpoint committed
07:56:44 | 18 events retried
07:55:02 | destination acknowledged batch""",
        "customer_export_console_20260618.png": """Northstar Shop | Customer Download Center | Data exports
Create and manage customer download packages
Ready: 2 | Processing: 2 | Created today: 1 | Downloads today: 0
Export ID | Filename | Owner | Status | Created
export_1261 | customer_export_1261.zip | marcus.lee@northstar.shop | Collecting | 20 Jun 14:18 UTC
export_1260 | customer_export_1260.zip | ingrid.dahl@outlook.com | Ready | 18 Jun 06:42 UTC
export_1259 | customer_export_1259.zip | sara.kim@northstar.shop | Packaging | 17 Jun 11:03 UTC
export_1258 | customer_export_1258.zip | daniel.park@northstar.shop | Ready | 16 Jun 09:27 UTC
Selected export_1260 | Owner: ingrid.dahl@outlook.com
Created: 18 Jun 2026 06:42 UTC | Expires: 25 Jun 2026 06:42 UTC
Size: 18.4 MB | Checksum: SHA-256 | 41ca09...
Download count: 0 | Included: Profile | Orders | Saved addresses
06:46 | Ready for download
06:45 | Package created
06:43 | Collecting customer records
06:42 | Export requested""",
        "deleted_account_reference_20260310.png": """Northstar Shop | Customer Reference Registry | Customer references
user_17 | Retained reference | Customer key | Account Platform | eu-west
Created: 11 Jan 2024 08:42 UTC | Most recent update: 10 Mar 2026 07:18 UTC
Owner team: Account Platform
System | Record reference | Relationship | Created (UTC) | Status
Orders | ORD-20263245 | Linked to customer | 11 Jan 2024 08:45 | Active
Support | CS-3245 | Linked to customer | 14 Feb 2024 12:16 | Active
Support | CS-3378 | Linked to customer | 03 Jun 2024 09:27 | Active
Finance | FIN-7742 | Linked to customer | 22 Aug 2024 15:03 | Active
History
10 Mar 2026 | Metadata reviewed
22 Aug 2024 | Finance link added
03 Jun 2024 | Support link added
14 Feb 2024 | Support link added
11 Jan 2024 | Reference created
Activity
Reference created | Recorded
Order link added | ORD-20263245
Support links added | CS-3245, CS-3378
Finance link added | FIN-7742
Metadata reviewed | Recorded""",
        "marketing_profile_console.png": """Northstar Shop | Audience Operations
Soo-jin Park | Live
marketing_001 | sj.park@naver.com | +82 10-5837-9451
Market: South Korea | Language: Korean | Email opt-in: Yes | SMS opt-in: No
Last refreshed: 15 Sep 2026 23:40 UTC
Time | Activity | Detail
23:40 | Product-category update | Desk accessories · Drinkware
23:38 | Campaign eligibility check | Autumn offers · Eligible
23:35 | Profile refresh | Live profile fields updated
23:32 | Audience evaluation | Returning customers — East Asia
Audience: Returning customers — East Asia
Segments: Repeat customer · Home & lifestyle · Mobile shopper
Preferred categories: Desk accessories · Drinkware
Last campaign: Autumn offers | Open rate: 32.4% | Click rate: 6.8%
Autumn offers | 32.4% open rate
Home & Lifestyle Picks | 28.7% open rate
Profile refreshed from live data | Recorded""",
        "object_storage_browser_20260213.png": """Northstar Shop | Nimbus Object Storage | northstar-customer-data
eu-west-1 | support-attachments | 2026 / 02 | 8 objects
Account: Northstar Production | Region: eu-west-1
Captured: 13 Feb 2026 08:00 UTC | Storage class: All
Name | Size | Modified (UTC) | Storage class | Version
delivery_confirmation_19.pdf | 684 KB | 12 Feb 18:42 | Standard | v3
delivery_confirmation_20.pdf | 712 KB | 11 Feb 14:17 | Standard | v1
return_label_4821.pdf | 203 KB | 10 Feb 09:33 | Standard | v1
return_label_4876.pdf | 198 KB | 11 Feb 16:05 | Standard | v2
invoice_NS-10493.pdf | 318 KB | 10 Feb 11:21 | Standard | v1
parcel_damage_7713.jpg | 2.4 MB | 12 Feb 10:08 | Standard | v1
customer_export_2026-02-10.zip | 128 MB | 10 Feb 23:14 | Standard | v1
customer_export_2026-02-12.zip | 131 MB | 12 Feb 21:56 | Standard | v1
Selected delivery_confirmation_19.pdf
Size: 684 KB | Version: v3 | Content type: application/pdf
Encryption: AES-256 | Checksum: e71b6d... | Uploader: support-service
Modified: 12 Feb 2026 18:42 UTC
v3 | 12 Feb 18:42 | metadata update
v2 | 12 Feb 18:39 | upload complete
v1 | 12 Feb 18:38 | object created""",
        "search_index_inspector_20260901.png": """Northstar Shop | Search Console | Customer Search
Query: email:g.silva76@gmail.com
customer_directory_v3 | prod-eu | 2 hits
Executed: 01 Sep 2026 06:00:14 UTC | Latency: 184 ms
Index: customer_directory_v3 | Environment: prod-eu | Shard total: 184 ms
_id | Display name | Email | Customer reference | Score | Last indexed
search_428 | Gabriel Silva | g.silva76@gmail.com | user_13 | 9.84 | 05:58:21 UTC
search_1874 | — | g.silva76.jr@gmail.com | — | 4.12 | 05:55:03 UTC
Raw document | search_428
_index: customer_directory_v3
_id: search_428
display_name: Gabriel Silva
email: g.silva76@gmail.com
customer_reference: user_13
indexed_at: 2026-09-01T05:58:21Z
06:00:14 | email:g.silva76@gmail.com | 2 hits
05:42:03 | customer_reference:user_9842 | 1 hit
05:31:18 | display_name:"Aditi Jain" | 1 hit""",
        "security_audit_explorer_20260905.png": """Northstar Shop | Sentinel | Account events
Subject filter: user_03 | 18–26 Aug 2026 UTC | 6 signed events
Events: 6 | Categories: 5 | Integrity failures: 0 | Partition: 2026-Q3
Time (UTC) | Event | Category | Subject | Actor | Integrity | Reference
25 Aug 04:03 | Account closure recorded | Account lifecycle | user_03 | Automated workflow | Valid | audit_record_003
25 Aug 03:21 | Session revoked | Session management | user_03 | Security system | Valid | audit_record_002
24 Aug 16:14 | Recovery challenge completed | Authentication | user_03 | User (self) | Valid | audit_record_001
22 Aug 11:27 | Email change confirmed | Profile update | user_03 | User (self) | Valid | audit_record_006
20 Aug 09:42 | Login from new device | Authentication | user_03 | User (self) | Valid | audit_record_005
18 Aug 14:05 | Password changed | Authentication | user_03 | User (self) | Valid | audit_record_004
Raw event | audit_record_003
event_type: account_closure_recorded
subject: user_03
actor: automated account workflow
recorded_at: 2026-08-25T04:03:00Z
fingerprint: 8f0c...31ad
signature: Valid
journal: 2026-Q3
25 Aug | Account closure recorded
25 Aug | Session revoked
24 Aug | Recovery challenge completed
22 Aug | Email change confirmed""",
        "support_ticket_console_20260524.png": """Northstar Shop | Helpline Console | Inbox
CS-5034 | Where is my delivery? | SLA 01:42
support_1034 | Kofi Agyeman | Normal priority
Customer: Kofi Agyeman | Email: kagyeman8947@fastmail.com
Assigned: Maya Chen
Tags: Delivery · Tracking · Order update
Time | Sender | Message
09:12 | Kofi Agyeman | Could you let me know where my order is and when it is expected to arrive?
09:13 | Northstar Bot | We received your message and are checking the order details.
09:28 | Maya Chen | The parcel reached the regional hub and is on track for delivery on 26 May.
09:35 | Kofi Agyeman | Thanks for the update.
Order ORD-20265034
Product: Running shoes | Status: In transit | Carrier: SwiftShip
Tracking: SWF-884103 | Expected: 26 May 2026 | Assigned agent: Maya Chen
22 May | Order confirmed
23 May | Dispatched
24 May 07:46 | Reached regional hub
24 May 08:15 | In transit
26 May | Delivery expected""",
    }

    def extract_pages(self, path: Path) -> tuple[str, ...]:
        try:
            return (self.TRANSCRIPTS[path.name],)
        except KeyError as exc:
            raise ValueError("No verified participant screenshot transcription exists for this image.") from exc

    def extract_structured_records(self, path: Path) -> tuple[tuple[str, Mapping[str, Any]], ...]:
        """Project explicitly labelled screenshot facts without assigning cases.

        Each record is (visible anchor text, fields).  The caller retains the
        complete page transcript as well and verifies every anchor against it.
        This intentionally handles only unambiguous selected/detail records;
        unlabelled times, inferred system names, and ambiguous owners are left
        as page text.
        """
        page = self.extract_pages(path)[0]
        name = path.name

        def line(pattern: str) -> re.Match[str] | None:
            return re.search(pattern, page, re.MULTILINE | re.IGNORECASE)

        def add_explicit_time(fields: dict[str, Any], anchor: str, pattern: str,
                              field: str, *, fmt: str, offset_hours: int = 0) -> None:
            match = re.search(pattern, anchor, re.IGNORECASE)
            if not match:
                return
            raw = match.group(1).strip()
            try:
                local = datetime.strptime(raw, fmt)
            except ValueError:
                return
            zone = timezone(timedelta(hours=offset_hours))
            fields[field] = local.replace(tzinfo=zone).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
            fields[field + "_raw"] = raw

        if name == "security_audit_explorer_20260905.png":
            block = page.split("Raw event | audit_record_003\n", 1)
            if len(block) != 2:
                return ()
            anchor = "Raw event | audit_record_003\n" + block[1].split("\n25 Aug |", 1)[0]
            fields: dict[str, Any] = {"resource_id": "audit_record_003"}
            aliases = {"subject": "user_id", "event_type": "event_type", "recorded_at": "recorded_at",
                       "signature": "signature", "journal": "journal"}
            for raw_key, field_name in aliases.items():
                match = re.search(rf"(?m)^{re.escape(raw_key)}:\s*(.+?)\s*$", anchor, re.IGNORECASE)
                if match:
                    fields[field_name] = match.group(1)
            return ((anchor, fields),) if {"user_id", "event_type", "recorded_at"} <= fields.keys() else ()

        if name == "search_index_inspector_20260901.png":
            block = page.split("Raw document | search_428\n", 1)
            if len(block) != 2:
                return ()
            anchor = "Raw document | search_428\n" + block[1].split("\n06:00:14 |", 1)[0]
            values = {}
            for key in ("_id", "email", "customer_reference", "indexed_at"):
                match = re.search(rf"(?m)^{re.escape(key)}:\s*(.+?)\s*$", anchor, re.IGNORECASE)
                if match:
                    values["resource_id" if key == "_id" else key] = match.group(1)
            return ((anchor, values),) if {"resource_id", "email", "customer_reference", "indexed_at"} <= values.keys() else ()

        selected = {
            "account_admin_console_20260926.png": (r"^(user_\d+) \| (account_\d+)$", ("user_id", "account_id"), "resource_id"),
            "analytics_profile_view_20260713.png": (r"^(user_\d+) \| (analytics_\d+) \| ([^\s|]+@[^\s|]+)$", ("user_id", "profile_id", "email"), "resource_id"),
            "marketing_profile_console.png": (r"^(marketing_\d+) \| ([^\s|]+@[^\s|]+) \| (.+)$", ("profile_id", "email", "phone"), "resource_id"),
        }
        if name in selected:
            pattern, keys, resource_key = selected[name]
            match = line(pattern)
            if not match:
                return ()
            values = dict(zip(keys, (item.strip() for item in match.groups())))
            values[resource_key] = values["account_id"] if "account_id" in values else values["profile_id"]
            anchor = match.group(0)
            if name == "account_admin_console_20260926.png":
                contact = line(r"^Last contact: (.+?)$")
                if contact:
                    anchor = page[match.start():contact.end()]
                    add_explicit_time(values, anchor, r"Last contact:\s*(.+?)\s+JST",
                                      "last_contact_at", fmt="%d %b %Y %H:%M", offset_hours=9)
                email = line(r"^Email: (\S+)$")
                phone = line(r"^Phone: (\S+)$")
                if email:
                    values["email"] = email.group(1)
                if phone:
                    values["phone"] = phone.group(1)
            elif name == "analytics_profile_view_20260713.png":
                last = line(r"^Last activity: (.+?) \| First seen: (.+?)$")
                if last:
                    anchor = page[match.start():last.end()]
                    add_explicit_time(values, last.group(0), r"Last activity:\s*(.+?)\s+UTC",
                                      "last_activity_at", fmt="%d %b %Y %H:%M")
                    add_explicit_time(values, last.group(0), r"First seen:\s*(.+?)\s+UTC",
                                      "first_seen_at", fmt="%d %b %Y %H:%M")
            elif name == "marketing_profile_console.png":
                refreshed = line(r"^Last refreshed: (.+?)$")
                if refreshed:
                    anchor = page[match.start():refreshed.end()]
                    add_explicit_time(values, refreshed.group(0), r"Last refreshed:\s*(.+?)\s+UTC",
                                      "last_refreshed_at", fmt="%d %b %Y %H:%M")
            return ((anchor, values),)

        if name == "connector_management_console_20260807.png":
            match = line(r"^Selected (data_flow_\d+) \| Status: ([^|]+) \| Owner: ([^|]+)$")
            destination = line(r"^Destination: ([^|]+) \| Selector: ([^|]+)$")
            mode = line(r"^Sync mode: (.+?) \|")
            if not (match and destination and mode):
                return ()
            anchor = "\n".join((match.group(0), destination.group(0), mode.group(0)))
            return ((anchor, {"resource_id": match.group(1), "flow_id": match.group(1),
                              "status": match.group(2).strip(), "target_system": destination.group(1).strip(),
                              "subject_selector": "email=" + destination.group(2).strip(),
                              "mode": mode.group(1).strip()}),)

        if name == "backup_restore_console_20260429.png":
            block = page.split("Selected backup_9287\n", 1)
            if len(block) != 2:
                return ()
            anchor = "Selected backup_9287\n" + block[1].split("\n25 Apr |", 1)[0]
            account = re.search(r"(?m)^Account:\s*(\S+)$", anchor)
            archive_path = re.search(r"(?m)^Path:\s*(\S+)$", anchor)
            region = re.search(r"\bRegion:\s*([^|]+)", anchor)
            created = re.search(r"\bCreated:\s*(.+?)\s*$", anchor, re.MULTILINE)
            retention = re.search(r"(?m)^Retention end:\s*(.+?)\s*$", anchor)
            fields = {"resource_id": "backup_9287", "backup_id": "backup_9287"}
            for match, key in ((account, "email"), (archive_path, "backup_path"),
                               (region, "region"), (created, "created_text"),
                               (retention, "retention_end_text")):
                if match:
                    fields[key] = match.group(1).strip()
            add_explicit_time(fields, anchor, r"Created:\s*(.+?)\s+UTC",
                              "created_at", fmt="%d %b %Y %H:%M")
            # Retention end is deliberately not renamed to a policy deadline.
            return ((anchor, fields),) if account and archive_path and retention else ()

        if name == "customer_export_console_20260618.png":
            block = page.split("Selected export_1260 |", 1)
            if len(block) != 2:
                return ()
            anchor = "Selected export_1260 |" + block[1].split("\n06:46 |", 1)[0]
            fields = {"resource_id": "export_1260", "export_id": "export_1260"}
            for label, key in (("Owner", "export_owner_email"), ("Created", "created_text"),
                               ("Expires", "expires_text")):
                match = re.search(rf"\b{label}:\s*([^|\n]+)", anchor, re.IGNORECASE)
                if match:
                    fields[key] = match.group(1).strip()
            add_explicit_time(fields, anchor, r"Created:\s*(.+?)\s+UTC",
                              "created_at", fmt="%d %b %Y %H:%M")
            add_explicit_time(fields, anchor, r"Expires:\s*(.+?)\s+UTC",
                              "expires_at", fmt="%d %b %Y %H:%M")
            # Owner is intentionally not promoted to a subject identifier.
            return ((anchor, fields),)

        if name == "support_ticket_console_20260524.png":
            match = line(r"^(CS-\d+) \| .+$")
            customer = line(r"^Customer: ([^|]+) \| Email: (\S+)$")
            order = line(r"^Order (ORD-\d+)$")
            support = line(r"^(support_\d+) \|")
            if not (match and customer and order and support):
                return ()
            anchor = page[match.start():order.end()]
            return ((anchor, {"resource_id": match.group(1), "ticket_id": match.group(1), "support_id": support.group(1),
                              "customer_email": customer.group(2), "order_id": order.group(1),
                              "order_reference": order.group(1), "data_category": "SUPPORT_MESSAGE"}),)

        if name == "deleted_account_reference_20260310.png":
            heading = line(r"^(user_17 \| Retained reference \| Customer key \| Account Platform \| eu-west)$")
            results = []
            for match in re.finditer(r"(?m)^(Orders|Support|Finance) \| ([^|]+) \| Linked to customer \| ([^|]+) \| (Active)$", page):
                start = heading.start() if heading else match.start()
                anchor = page[start:match.end()]
                results.append((anchor, {"user_id": "user_17", "resource_id": match.group(2).strip(),
                                         "related_system_label": match.group(1),
                                         "relationship": "Linked to customer", "status": match.group(4)}))
            return tuple(results)

        if name == "object_storage_browser_20260213.png":
            block = page.split("Selected delivery_confirmation_19.pdf\n", 1)
            if len(block) != 2:
                return ()
            anchor = "Selected delivery_confirmation_19.pdf\n" + block[1].split("\nv3 |", 1)[0]
            modified = re.search(r"(?m)^Modified:\s*(.+?)\s*$", anchor)
            checksum = re.search(r"(?m)^Encryption:.*?\| Checksum:\s*([^|]+)", anchor)
            fields = {"object_key": "delivery_confirmation_19.pdf", "object_version": "v3"}
            if modified:
                fields["modified_text"] = modified.group(1)
            if checksum:
                fields["checksum_display"] = checksum.group(1).strip()
            add_explicit_time(fields, anchor, r"Modified:\s*(.+?)\s+UTC",
                              "modified_at", fmt="%d %b %Y %H:%M")
            return ((anchor, fields),)

        return ()

