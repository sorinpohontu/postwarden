import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "stubs"))

import Milter  # noqa: E402  (stub)

from postwarden import __version__, milter  # noqa: E402
from postwarden.__main__ import main  # noqa: E402
from postwarden.logging import format_event  # noqa: E402
from postwarden.policy import AuthStatus, AuthenticationInput, DkimOutcome, SpfOutcome  # noqa: E402
from postwarden.quota import QuotaStore  # noqa: E402
from postwarden.stats import parse_line, render, report, tally  # noqa: E402

from helpers import settings  # noqa: E402

LIMITS = '\n[sending_limits]\nmode = "enforce"\nper_hour = 2\nper_day = 10\n'
MULTIPLIERS = '\n[sending_limits.multipliers]\n"example.com" = 3\n"example.org" = 2\n'


class JournalLogger:
    """Writes what the daemon would send to syslog, as `journalctl -o short-iso` shows it."""

    def __init__(self, level="info"):
        self.lines = []
        self.level = level

    def event(self, level="info", **fields):
        order = ("debug", "info", "warning", "error")
        if order.index(level) >= order.index(self.level):
            self.lines.append(f"2026-09-28T10:00:00+0200 host postwarden[42]: {format_event(fields)}\n")

    info = lambda self, **f: self.event("info", **f)
    warning = lambda self, **f: self.event("warning", **f)
    debug = lambda self, **f: self.event("debug", **f)
    error = lambda self, **f: self.event("error", **f)

    def start(self, level="info"):
        self.lines.append(f"2026-09-28T09:00:00+0200 host postwarden[42]: {format_event({'event': 'start', 'logging_level': level})}\n")


def passing(*a, **k):
    return AuthenticationInput(SpfOutcome(AuthStatus.PASS, "example.org", "pass"), (DkimOutcome(AuthStatus.PASS, "example.org"),))


class Traffic:
    def __init__(self, test, mode="enforce", extra=LIMITS, level="info"):
        self.log = JournalLogger(level)
        self.log.start(level)
        self.cfg = settings(f'\nmode = "{mode}"\n' + extra)
        self.quota = None if self.cfg.sending_limits.mode == "off" else QuotaStore(self.cfg.sending_limits)
        milter.authenticator = passing
        test.addCleanup(setattr, milter, "authenticator", None)
        self.activate()

    def activate(self):
        milter.configure(self.cfg, self.log, self.quota)

    def send(self, sender, rcpts, *, login=None, port="587", peer="198.51.100.7", pickup=False, from_header=None):
        self.activate()
        m = milter.PolicyMilter()
        m.macros, m.replies = {}, []
        m.negotiate([0x1ff, 0x1fffff, 0, 0])
        if pickup:
            m.macros.update({"{daemon_port}": "0", "{postwarden_ingress}": "LOCAL_PICKUP"})
            m.connect("localhost", 2, ("127.0.0.1", 0))
        else:
            ingress = {"25": "SMTP25", "587": "SUBMISSION587"}[port]
            m.macros.update({"{daemon_port}": port, "{postwarden_ingress}": ingress, "{auth_type}": "PLAIN" if login else None,
                             "{auth_authen}": login, "{cipher_bits}": "256" if login else None, "i": "Q1"})
            m.connect("client", 2, (peer, 1234))
            m.hello("client.example")
        m.envfrom(f"<{sender}>")
        codes = [m.envrcpt(f"<{r}>") for r in rcpts]
        m.header("From", f" {from_header or sender}")
        m.eoh()
        m.body(b"hi\r\n")
        rc = m.eom()
        m.close()
        return codes, rc


def build(traffic, config=LIMITS + MULTIPLIERS, top=20):
    return report(tally(traffic.log.lines), settings(config).sending_limits, source={"description": "test"},
                  config="test.toml", top=top, notes=[])


class Parsing(unittest.TestCase):
    def test_quoted_values_and_other_programs(self):
        stamp, fields = parse_line('2026-09-28T10:00:00+0200 h postwarden[1]: action=reject reply="550 5.7.1 a \\"b\\" (ref x)" '
                                   'rcpt=a@b sender="odd\\x20name"\n')
        self.assertEqual((stamp, fields["reply"], fields["sender"]), ("2026-09-28T10:00:00+0200", '550 5.7.1 a "b" (ref x)', "odd name"))
        self.assertIsNone(parse_line("2026-09-28T10:00:00 h postfix/smtpd[1]: action=reject rule=x\n"))
        self.assertIsNone(parse_line("2026-09-28T10:00:00 h postwarden[1]: /etc/postwarden/config.toml: OK (schema 1)\n"))


class Measures(unittest.TestCase):
    def test_delivered_counts_only_refusals_sent(self):
        traffic = Traffic(self)
        traffic.send("demo@example.com", ["a@example.net", "all@example.com", "b@example.net"], login="demo@example.com")
        data = build(traffic)
        self.assertEqual(data["totals"], {"messages": 1, "delivered": 2, "allowed": 2, "unmeasured": 0})
        self.assertEqual(data["refusals"], [{"action": "reject", "rule": "protected_recipient",
                                             "reason": "login_not_authorized", "scope": "recipient", "count": 1}])

    def test_same_message_in_observe_and_enforce(self):
        rcpts = ["a@example.net", "all@example.com", "b@example.net"]
        enforce, observe = Traffic(self), Traffic(self, mode="observe")
        enforce.send("demo@example.com", rcpts, login="demo@example.com")
        observe.send("demo@example.com", rcpts, login="demo@example.com")
        self.assertEqual(build(enforce)["totals"]["delivered"], 2)
        observed = build(observe)
        self.assertEqual((observed["totals"]["delivered"], observed["totals"]["allowed"]), (3, 2))
        self.assertEqual(observed["refusals"], [])
        self.assertEqual(observed["observed"][0]["action"], "would_reject")

    def test_observed_message_refusal_is_delivered_but_not_allowed(self):
        traffic = Traffic(self, mode="observe")
        milter.authenticator = lambda *a, **k: AuthenticationInput(SpfOutcome(AuthStatus.FAIL, None, "fail"), dkim_skipped=True)
        traffic.send("bob@example.org", ["carol@example.com"], port="25")
        data = build(traffic)
        self.assertEqual(data["totals"], {"messages": 1, "delivered": 1, "allowed": 0, "unmeasured": 0})
        self.assertEqual(data["observed"][0]["scope"], "message")

    def test_limit_deferrals_by_key_and_untrusted_mail_in_totals_only(self):
        traffic = Traffic(self)
        traffic.send("demo@example.com", ["a@example.net", "b@example.net", "c@example.net"], login="demo@example.com")
        traffic.send("bob@example.org", ["carol@example.com"], port="25")
        data = build(traffic, config=LIMITS)
        self.assertEqual(data["totals"]["delivered"], 3)
        self.assertEqual(data["senders_total"], 1)
        sender = data["senders"][0]
        self.assertEqual((sender["limit_key"], sender["delivered"], sender["limit_deferred"], sender["per_hour"], sender["per_day"]),
                         ("demo@example.com", 2, 1, 2, 10))

    def test_ranking_uses_the_selected_configuration(self):
        traffic = Traffic(self)
        traffic.send("demo@example.com", ["a@example.net"], login="demo@example.com")
        self.assertEqual(build(traffic)["senders"][0]["per_hour"], 6)
        self.assertEqual(build(traffic, config=LIMITS)["senders"][0]["per_hour"], 2)

    def test_short_login_gets_a_row_per_sender_domain(self):
        traffic = Traffic(self, extra=LIMITS + MULTIPLIERS)
        traffic.send("john@example.com", ["a@example.net"], login="john")
        traffic.send("john@example.org", ["a@example.net", "b@example.net"], login="john")
        row = build(traffic)["senders"][0]
        self.assertEqual((row["limit_key"], row["delivered"], row["per_hour"]), ("login:john", 3, None))
        self.assertEqual([(d["sender_domain"], d["delivered"], d["per_hour"]) for d in row["by_sender_domain"]],
                         [("example.org", 2, 4), ("example.com", 1, 6)])
        own = build(traffic, config=LIMITS + MULTIPLIERS + '"login:john" = 5\n')["senders"][0]
        self.assertEqual((own["per_hour"], "by_sender_domain" in own), (10, False))

    def test_limits_off_still_ranks_senders_and_says_so(self):
        traffic = Traffic(self, extra='\n[sending_limits]\nmode = "off"\n')
        traffic.send("demo@example.com", ["a@example.net"], login="demo@example.com")
        data = build(traffic)
        self.assertEqual(data["senders"][0]["limit_key"], "demo@example.com")
        self.assertIn("sending limits were off for some or all of the period (limit_measured=off)", data["notes"])

    def test_unmeasured_recipients_have_their_own_column_without_the_rcpt_line(self):
        traffic = Traffic(self, extra=LIMITS.replace("enforce", "observe"))
        traffic.quota.capacity = 0
        traffic.send("demo@example.com", ["a@example.net"], login="demo@example.com")
        lines = [line for line in traffic.log.lines if "stage=rcpt" not in line]
        data = report(tally(lines), settings(LIMITS).sending_limits, source={"description": "t"}, config="c",
                      top=20, notes=[])
        self.assertEqual((data["totals"]["unmeasured"], data["senders"][0]["unmeasured"]), (1, 1))

    def test_held_local_mail_counts_one_deferral_per_retry(self):
        traffic = Traffic(self, extra=LIMITS)
        for _ in range(3):
            traffic.send("web@example.com", ["a@example.net", "b@example.net", "c@example.net"], pickup=True)
        data = build(traffic, config=LIMITS)
        self.assertEqual(data["totals"]["messages"], 0)
        self.assertEqual(data["senders"][0]["limit_deferred"], 3)
        self.assertEqual(data["refusals"][0]["scope"], "message")

    def test_spread_and_concentrated_traffic_give_the_same_totals(self):
        off = '\n[sending_limits]\nmode = "off"\n'
        spread, burst = Traffic(self, extra=off), Traffic(self, extra=off)
        for n in range(4):
            spread.send("demo@example.com", [f"r{n}@example.net"], login="demo@example.com")
        burst.send("demo@example.com", [f"r{n}@example.net" for n in range(4)], login="demo@example.com")
        self.assertEqual(build(spread)["totals"]["delivered"], build(burst)["totals"]["delivered"])
        self.assertEqual(build(spread)["senders"][0]["delivered"], build(burst)["senders"][0]["delivered"])
        self.assertNotIn("near", "\n".join(render(build(spread))).lower())


class ObservedRefusalAtMail(unittest.TestCase):
    def test_message_let_through_after_a_mail_stage_refusal_has_an_eom_line_and_counts_once(self):
        traffic = Traffic(self, mode="observe", extra='\n[limits]\nmax_open_messages = 1\n')
        traffic.activate = lambda: None
        milter._open_slots.acquire()
        self.addCleanup(milter._open_slots.release)
        codes, rc = traffic.send("demo@example.com", ["a@example.net", "b@example.net"], login="demo@example.com")
        self.assertEqual((codes, rc), ([Milter.CONTINUE, Milter.CONTINUE], Milter.CONTINUE))
        eom = [parse_line(line)[1] for line in traffic.log.lines if "stage=eom" in line]
        self.assertEqual(len(eom), 1)
        self.assertEqual((eom[0]["action"], eom[0]["reason"], eom[0]["rcpts"], eom[0]["limit_key"]),
                         ("would_defer", "max_open_messages", "2", "demo@example.com"))
        data = build(traffic)
        self.assertEqual(data["totals"], {"messages": 1, "delivered": 2, "allowed": 0, "unmeasured": 0})
        self.assertEqual(data["observed"], [{"action": "would_defer", "rule": "limits", "reason": "max_open_messages",
                                             "scope": "message", "count": 1}])
        mail_only = [line for line in traffic.log.lines if "stage=eom" not in line]
        self.assertEqual(report(tally(mail_only), settings().sending_limits, source={"description": "t"}, config="c",
                                top=20, notes=[])["observed"][0]["count"], 1)


class Text(unittest.TestCase):
    """Boxed tables; columns and sections that carry nothing are left out."""

    def lines(self, traffic):
        result = tally(traffic.log.lines)
        data = report(result, settings(LIMITS + MULTIPLIERS).sending_limits, source={"description": "test"},
                      config="test.toml", top=20, notes=[])
        return render(data, (result.first, result.last))

    def section(self, out, title):
        start = out.index(title) + 1
        end = next((i for i in range(start, len(out)) if not out[i]), len(out))
        return out[start:end]

    def test_enforce_period_hides_allowed_observe_and_zero_columns(self):
        traffic = Traffic(self)
        traffic.send("demo@example.com", ["a@example.net"], login="demo@example.com")
        out = self.lines(traffic)
        self.assertEqual(out[0][0], "+")
        self.assertIn("| Period     | 2026-09-28T09:00:00+0200 to 2026-09-28T10:00:00+0200 |", out)
        self.assertEqual(self.section(out, "Totals"), [
            "+----------------------+-------+", "| measure              | count |", "+----------------------+-------+",
            "| messages accepted    |     1 |", "| recipients delivered |     1 |", "+----------------------+-------+"])
        self.assertEqual(self.section(out, "Refusals sent"), ["none"])
        self.assertNotIn("Observe mode: refusals not sent", out)
        senders = self.section(out, "Senders by recipients delivered (top 1 of 1)")
        self.assertEqual(senders[1], "| limit key        | messages | delivered | limit h/d |")
        self.assertEqual(senders[3], "| demo@example.com |        1 |         1 |      6/30 |")
        self.assertIn("Recipients allowed equal delivered: no observe-mode refusals.", out)

    def test_observe_period_shows_allowed_and_the_observed_refusals(self):
        traffic = Traffic(self, mode="observe", extra=LIMITS.replace("enforce", "observe"))
        traffic.send("demo@example.com", ["a@example.net", "b@example.net", "c@example.net"], login="demo@example.com")
        out = self.lines(traffic)
        self.assertIn("| recipients allowed   |     2 |", self.section(out, "Totals"))
        observed = self.section(out, "Observe mode: refusals not sent")
        self.assertIn("| would_defer | sending_limit | per_hour | recipient |     1 |", observed)
        senders = self.section(out, "Senders by recipients delivered (top 1 of 1)")
        self.assertEqual(senders[1], "| limit key        | messages | delivered | allowed | would defer | limit h/d |")
        self.assertEqual(senders[3], "| demo@example.com |        1 |         3 |       2 |           1 |      6/30 |")
        self.assertNotIn("Recipients allowed equal delivered: no observe-mode refusals.", out)

    def test_header_names_version_and_host_when_given(self):
        traffic = Traffic(self)
        result = tally(traffic.log.lines)
        data = {"version": "9.9", "host": "mx1", **report(result, settings().sending_limits, source={"description": "t"},
                                                        config="c", top=20, notes=[])}
        self.assertTrue(render(data, (result.first, result.last))[1].startswith("| postwarden | 9.9 on mx1  "))

    def test_syslog_file_timestamps_keep_date_and_time(self):
        line = "Sep 29 11:37:13 vstore postwarden[1]: event=start logging_level=info\n"
        self.assertEqual(parse_line(line)[0], "Sep 29 11:37:13")


class Completeness(unittest.TestCase):
    def test_level_above_info_or_missing_start_line_is_reported(self):
        traffic = Traffic(self, level="warning")
        self.assertFalse(build(traffic)["complete"])
        self.assertIn("logging level warning", build(traffic)["notes"][0])
        self.assertFalse(report(tally([]), settings().sending_limits, source={"description": "t"}, config="c",
                                top=20, notes=[])["complete"])
        self.assertTrue(build(Traffic(self))["complete"])
        unknown = report(tally(["2026-09-28T09:00:00+0200 h postwarden[1]: event=start mode=enforce\n"]),
                         settings().sending_limits, source={"description": "t"}, config="c", top=20, notes=[])
        self.assertEqual(unknown["notes"], ["start at 2026-09-28T09:00:00+0200 did not log its logging level: "
                                            "decisions may be missing after it"])
        two = report(tally(["2026-09-28T09:00:00+0200 h postwarden[1]: event=start mode=enforce\n",
                            "2026-09-28T10:00:00+0200 h postwarden[2]: event=start mode=enforce\n"]),
                     settings().sending_limits, source={"description": "t"}, config="c", top=20, notes=[])
        self.assertEqual(two["notes"], ["2 starts between 2026-09-28T09:00:00+0200 and 2026-09-28T10:00:00+0200 did "
                                        "not log their logging level: decisions may be missing after them"])


class Command(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.dir = directory.name
        self.config = os.path.join(self.dir, "config.toml")
        with open(self.config, "w") as fh:
            fh.write('schema_version = 1\n[protection.addresses."all@example.com"]\nauthorized_logins = []\n')

    def run_stats(self, *argv):
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out, \
             mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            status = main(["--config", self.config, "stats", *argv])
        return status, out.getvalue(), err.getvalue()

    def test_files_give_whole_file_totals_and_are_labelled_unverified(self):
        traffic = Traffic(self)
        traffic.send("demo@example.com", ["a@example.net"], login="demo@example.com")
        path = os.path.join(self.dir, "mail.log")
        with open(path, "w") as fh:
            fh.writelines(traffic.log.lines)
            fh.write("2026-09-28T11:00:00+0200 host postwarden[99]: action=accept stage=eom rcpts=500 limit_key=forged@example.com\n")
        status, out, _ = self.run_stats("--file", path, "--json")
        data = json.loads(out)
        self.assertEqual(status, 0)
        self.assertFalse(data["source"]["verified"])
        self.assertIn("whole-file totals: --since does not apply to files", data["notes"])
        self.assertEqual(data["totals"]["delivered"], 501)
        status, out, _ = self.run_stats("--file", path)
        self.assertIn("| Source     | files /", out)
        self.assertIn("(unverified:", out.splitlines()[4])

    def test_since_is_refused_with_files(self):
        status, _, err = self.run_stats("--file", "/nonexistent", "--since", "-1h")
        self.assertEqual(status, 2)
        self.assertIn("--since applies to the journal only", err)

    def test_journal_is_read_by_unit_for_the_last_day(self):
        from postwarden import logsource
        fake = mock.Mock(stdout=iter([]), stderr=mock.Mock(read=lambda: ""), wait=lambda: 0)
        with mock.patch.object(logsource.shutil, "which", return_value="/bin/journalctl"), \
             mock.patch.object(logsource.subprocess, "Popen", return_value=fake) as popen, \
             mock.patch.object(logsource, "journal_start", return_value=None):
            status, out, _ = self.run_stats()
        argv = popen.call_args.args[0]
        self.assertEqual(status, 0)
        self.assertIn("_SYSTEMD_UNIT=postwarden.service", argv)
        self.assertEqual(argv[-2:], ["--since", "-24h"])
        self.assertIn("(verified)", out.splitlines()[4])
        self.assertTrue(out.splitlines()[1].startswith("| postwarden | "))
        self.assertIn("| Period     | no postwarden lines", out)

    def test_json_carries_version_and_host(self):
        path = os.path.join(self.dir, "mail.log")
        open(path, "w").close()
        data = json.loads(self.run_stats("--file", path, "--json")[1])
        self.assertEqual(data["version"], __version__)
        self.assertTrue(data["host"])


if __name__ == "__main__":
    unittest.main()
