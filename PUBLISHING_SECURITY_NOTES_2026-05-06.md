# Publishing Security Notes (2026-05-06)

## What was removed/sanitized before GitHub publish

1. Hardcoded NVD API key removed from `docker-compose.yml`.
   - Removed value: `0a27bb6d-ad6c-4d4e-a724-729569d8dc1e`
   - Replaced with: `NVD_API_KEY=${NVD_API_KEY:-}`

2. Hardcoded database credentials replaced by environment placeholders in `docker-compose.yml`.
   - `MYSQL_ROOT_PASSWORD: rootpassword` -> `${DB_ROOT_PASS:-change_me_root_password}`
   - `MYSQL_PASSWORD: security_pass` -> `${DB_PASS:-change_me_db_password}`
   - Service env values like:
     - `DB_USER=security_user` -> `DB_USER=${DB_USER:-security_user}`
     - `DB_PASS=security_pass` -> `DB_PASS=${DB_PASS:-change_me_db_password}`
     - `DB_NAME=unified_security` -> `DB_NAME=${DB_NAME:-unified_security}`

3. API gateway static JWT fallback secret removed from code.
   - File: `api-gateway/app.py`
   - Before: fixed hardcoded secret string in source code.
   - After: `JWT_SECRET` from environment, otherwise ephemeral runtime secret.

4. README examples sanitized.
   - `DB_PASS=security_pass` -> `DB_PASS=change_me_db_password`

5. `.env.example` updated with explicit external key placeholder.
   - Added: `NVD_API_KEY=`

6. Local packet capture files are now excluded from publication.
   - Untracked from git index (kept locally): `dhcp_capture.pcap`, `dhcp_capture.snapshot.pcap`
   - Added to `.gitignore`: `*.pcap`, `*.pcapng`, `*.cap`

7. Local crash/temp folders excluded from publication.
   - Added to `.gitignore`: `.edge-tmp/`, `.tmp_repo_suricata/`, `.tmp_tenyar_suricata/`, `Crashpad/`, `*.dmp`

8. Insecure hardcoded password defaults cleaned in service code/docs.
   - Replaced fallback `security_pass` with `change_me_db_password` in:
     - `api-gateway/app.py`
     - `services/traffic-analyzer/app.py`
     - `services/traffic-analyzer/app_simple.py`
     - `services/vulnerability-scanner/app.py`
     - `services/correlation-engine/app.py`
   - `.env.example` normalized:
     - `DB_PASS=change_me_db_password`
     - `DB_ROOT_PASS=change_me_root_password`
   - README DB check command now uses placeholder password (`-p<your_db_password>`).

## Private values you must keep locally (do not commit)

Store these in your local `.env` only:

- `DB_PASS`
- `DB_ROOT_PASS`
- `JWT_SECRET`
- `NVD_API_KEY` (if used)
- Any future `*_API_KEY`, `*_TOKEN`, `*_SECRET`

## Recommended next steps

1. Rotate the old NVD key (it was previously in source history).
2. Keep `.env` untracked (already ignored by `.gitignore`).
3. Before each push, run a secret scan:
   - `rg -n "(API_KEY|TOKEN|SECRET|PASSWORD|PASS=|JWT_SECRET|NVD_API_KEY)" -S`
