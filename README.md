# Tozzer Patient Tracker

Patient tracker for Dr. Charles Tozzer DDS, hosted on Cloudflare Pages with a D1 database.

## How it fits together

- `public/index.html` — the tracker. Each staff member signs in with their own username and password.
- `public/admin.html` — the admin page at `/admin`: killswitch, staff logins, activity log. Only admin logins can open it.
- `functions/` — the API (Cloudflare Pages Functions): sign-in, first-login setup, patient records, admin.
- `lib/` — shared helpers: password hashing, sessions, rate limits, audit log.
- `schema.sql` — database tables. Run it once against the D1 database before first use.

Nothing secret is in this repo. Passwords are stored only as salted PBKDF2 hashes in D1, and the cookie-signing key is generated inside the database on first use.

## Roles

| Role | Tracker | `/admin`: activity log, add / pause / reset / remove logins | Make managers | Killswitch |
| --- | --- | --- | --- | --- |
| Owner (`michael`) | ✓ | ✓ | ✓ | ✓ |
| Manager (`ctozzer`) | ✓ | ✓ — every login except the owner's | — | — |
| Staff | ✓ | — | — | — |

Nobody can pause, remove or reset their own login from the page, and the owner's login can't be changed by anyone else. Use **Change my password** for your own login.

## Staff logins

On `/admin`, enter a username and choose **Create login**. The page shows a temporary password once; pass both to the staff member. On their first sign-in they are asked, once, whether they want to choose their own username and password or keep the ones they were given. **New password** issues a fresh temporary password (and asks again on their next sign-in), **Pause** blocks a login without deleting it, **Remove** deletes it.

## Killswitch

On `/admin`, choose **Take site offline**. The admin page keeps working while the site is offline. Every page and API call then returns an "unavailable" notice, everyone is signed out, and nobody can sign in until you bring it back online. Records are kept, not deleted. **Sign everyone out** ends all sessions without taking the site down.

If `/admin` itself won't load: in Cloudflare open Storage & databases → D1 → this database → Console and run

```sql
UPDATE settings SET value = '1' WHERE key = 'offline';
```

Run it again with `'0'` to bring the site back.

## Safeguards

- Separate login per person; signed HttpOnly SameSite=Strict cookies; 12-hour sessions and 30-minute idle sign-out
- Rate limits: 8 wrong sign-ins per device per 15 minutes, 5 wrong admin sign-ins per 30 minutes
- Changing, resetting, pausing or removing a login ends that person's sessions immediately
- Audit log of sign-ins, failed attempts, login changes and every patient change with the username
- Fails closed: if the database can't be reached, the site shows the unavailable page
- Not indexed by search engines; strict security headers

## Compliance note

This stores protected health information. Cloudflare signs a Business Associate Agreement only on Enterprise plans. Confirm the practice's HIPAA obligations before entering real patient data.
