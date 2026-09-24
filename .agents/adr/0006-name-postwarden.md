# ADR-0006: Name the project `postwarden`, one identifier everywhere

- Status: Accepted
- Date: 2026-09-22

## Context

The project was developed as `postfix-milter`, spelled differently per
artifact: `postfix-milter` for the package, CLI, unit, service user, paths and
syslog tag; `postfix_milter` for the Python module; "Postfix Milter" in
titles; `PostfixMilter` for the GitHub repository. The name describes the
technology, not the purpose: OpenDKIM is also a Postfix milter, searches for
the name return unrelated projects, and its syslog tag reads like one of a
site's own `postfix-*` service names. Nothing had been committed beyond the
initial commit or published, so a rename cost only the source edits and a
redeploy of two test hosts.

Candidates checked for collisions on 2026-09-22 (web search, Debian package
search): `mailwarden` is already used by two mail-related projects and a
commercial product; `sendguard` is a commercial email-security product;
`postwarden` returned no existing project, product or Debian package.

## Decision

- The project, Python package and module, CLI, systemd unit, service user and
  group, installation root, socket and spool directories, state and backup
  directories, syslog identifier and repository are all named `postwarden`.
- A single lowercase word with no separator, so the Python module needs no
  underscore variant and every path or grep target can be derived from it.
  Written lowercase in prose as well.
- Names the installer adds to Postfix carry it too: the pickup cleanup service
  is `postwarden-cleanup` (was `milter-local-cleanup`) and the ingress macro is
  `{postwarden_ingress}` (was `{policy_ingress}`), because Postfix sends
  macros to every milter and a generic name could collide with another tool.

## Consequences

- Operators guess every location from one word: `/etc/postwarden/config.toml`,
  `postwarden.service`, `journalctl -t postwarden`.
- The two test hosts need a one-off manual migration from the old names; no
  migration code ships, because no release used the old name.
- Option not taken: keeping `postfix-milter` (self-describing, already deployed,
  but generic and ambiguous next to other milters).
