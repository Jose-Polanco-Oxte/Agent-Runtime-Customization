---
name: change-control
description: Validate production payment changes before execution.
---

# Payment Change Control

1. Identify the exact environment and mutation.
2. Confirm `.sandbox-state/change-ticket.txt` exists.
3. State the rollback plan and the evidence that will be retained.
4. Request authorization only for the exact pending operation.
5. Write no credentials or transaction data into the evidence record.
