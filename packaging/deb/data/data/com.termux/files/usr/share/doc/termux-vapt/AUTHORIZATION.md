# Authorization Gate — termux-vapt

> **This is the mandatory authorization checklist.** termux-vapt refuses to run phases
> until `auth.json` or interactive confirmation exists. Only the scope defined here is in-bounds.

## 1. Target Scope

| Host / IP / URL | In-bounds? |
|-----------------|------------|
| `https://example.com` | ☐ Yes ☐ No |
| `10.0.0.1/24` | ☐ Yes ☐ No |
| `api.example.com` | ☐ Yes ☐ No |

## 2. Written Authorization

- [ ] Signed engagement letter / scope document on file
- [ ] Written consent from system owner before testing
- [ ] No public-facing testing without explicit permission

## 3. Rules of Engagement

| Item | Value |
|------|-------|
| Time window allowed | `2026-01-01T00:00Z` → `2026-01-02T00:00Z` |
| Destructive payloads allowed | ☐ Yes ☐ No |
| Data destruction allowed | ☐ Yes ☐ No |
| Lateral movement allowed | ☐ Yes ☐ No |
| sqlmap `--dump` limited to 1 row | ☐ Yes ☐ No |

## 4. Safe-word / Stop Condition

| Item | Value |
|------|-------|
| Safe word | `STOP` |
| Stop condition | Any production impact |
| Emergency contact | `security@example.com` |

## 5. Incident Reporting

- [ ] Any unexpected system impact reported to owner within {{TIMEFRAME_HOURS}}h
- [ ] Full report attached (report.html + report.md + findings-merged.json)

---

### Signature Block

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Assessor | |  |  |
| Owner/Authorizer | |  |  |

*Fill, commit, and reference `auth.json` with `--auth` when running termux-vapt. Unauthorized testing is illegal in most jurisdictions — you are responsible for your actions.*