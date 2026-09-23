# Mailent cloud release

Requested: a usable, private product with genuine data, routing, accessible UI and functioning capture/report workflows; host on Render with Supabase.

## Deployment

- Supabase: `vuskxbttfmmyxpqudjwv`, organization `yomqbuehrsgytvkrmjwp`, Singapore. Project exists and is healthy.
- Workspace owner: `seadeepie@gmail.com`.
- Render login verified. Service creation is pending.
- Database secrets are kept outside the repository and must never enter Git or browser bundles.

## Remaining release work

- [x] Complete Supabase Auth gate and server-side email authorization.
- [x] Verify PostgreSQL evidence persistence and apply private-schema migration.
- [x] Package frontend, API and Zeek capture processor together for Render.
- [ ] Verify real capture upload, navigation, report downloads and integration delivery.
- [ ] Deploy and check cloud authentication, API access controls and persistence.

## Implemented before cloud work

Real routes and URL search state, accessible upload and navigation dialogs, reduced-motion animations, consistent sidebar and one upload action, genuine empty/loading/error states, removal of fake workspace accounts/sample uploads, capture validation and timeouts, corrected integration contracts and report downloads. The last pre-cloud checks passed 9 frontend tests, production web build, and core/sensor compilation. These do not replace the release checks above.

## Current verification

- 9 frontend tests pass; production web build passes.
- Real browser capture upload, invalid-file rejection, findings, route reload, browser back and JSON download pass.
- Public root landing opens the separate `/workspace/overview` route.
- Supabase has 31 Mailent tables with RLS enabled, all in a private schema.
- PostgreSQL reconnect/conflict test passed in a temporary schema that was removed afterward.
- Authentication and syslog delivery tests pass.
- Render blueprint validation passes.
- Jev key is in ignored `.env` (0600), loading through dotenvy. Server pipeline is configured for Codiv and accurately labels fallback decisions. Local live calls currently time out; no live success is claimed.
- User's Steep reference implemented as serif landing page with warm paper, a peach section, readable semibold type and direct workspace entry. Desktop prioritized.
