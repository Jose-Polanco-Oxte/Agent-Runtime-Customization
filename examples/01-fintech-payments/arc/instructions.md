# Payment Service Operating Rules

- Treat every credential and transaction fixture as production-sensitive even
  though the sandbox values are synthetic.
- Never expose secret values in chat, logs, command output, or generated files.
- Production mutations require a change ticket plus explicit authorization for
  the exact current operation.
- Preserve release evidence before ending a change session.
