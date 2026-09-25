import os
import unittest
from pathlib import Path
from unittest import mock

from postwarden import deployment
from postwarden.deployment import DeploymentError, without_policy_call

SPF = "check_policy_service unix:private/policyd-spf"


class RemovePolicyCall(unittest.TestCase):
    def test_comma_separated(self):
        value = f"permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination, {SPF}"
        self.assertEqual(without_policy_call(value, "policyd-spf"),
                         "permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination")

    def test_whitespace_separated_keeps_other_restrictions(self):
        value = f"permit_mynetworks reject_unauth_destination {SPF} reject_rbl_client zen.example"
        self.assertEqual(without_policy_call(value, "policyd-spf"),
                         "permit_mynetworks reject_unauth_destination reject_rbl_client zen.example")

    def test_first_and_multiline_positions(self):
        self.assertEqual(without_policy_call(f"{SPF},\n    reject_unauth_destination", "policyd-spf"),
                         "reject_unauth_destination")
        self.assertEqual(without_policy_call(f"permit_mynetworks,\n    {SPF},\n    reject_unauth_destination",
                                             "policyd-spf"),
                         "permit_mynetworks,\n    reject_unauth_destination")

    def test_other_policy_services_untouched(self):
        value = "reject_unauth_destination, check_policy_service inet:127.0.0.1:10023"
        self.assertIs(without_policy_call(value, "policyd-spf"), value)

    def test_absent_is_noop(self):
        value = "permit_mynetworks, reject_unauth_destination"
        self.assertIs(without_policy_call(value, "policyd-spf"), value)
        self.assertEqual(without_policy_call("", "policyd-spf"), "")

    def test_braced_list_refused(self):
        with self.assertRaises(DeploymentError):
            without_policy_call("{ check_policy_service unix:private/policyd-spf, default_action=DUNNO }", "policyd-spf")


class RepeatedApplication(unittest.TestCase):
    SERVICES = {
        "submission/inet": "submission inet n - y - - smtpd -o smtpd_sasl_auth_enable=yes "
                           "-o milter_macro_defaults=postwarden_ingress=SUBMISSION587",
    }
    MAIN = {"milter_protocol": "6", "non_smtpd_milters": "$smtpd_milters"}

    def already(self, op):
        with mock.patch.object(deployment, "postconf", side_effect=lambda name, staging=None: self.MAIN.get(name, "")):
            return deployment._already_set(op, Path("/nonexistent"), self.SERVICES)

    def test_main_cf_value_in_place_is_skipped(self):
        self.assertTrue(self.already(["-e", "milter_protocol=6"]))
        self.assertTrue(self.already(["-e", "non_smtpd_milters=$smtpd_milters"]))
        self.assertFalse(self.already(["-e", "milter_protocol=2"]))

    def test_service_option_in_place_is_skipped(self):
        self.assertTrue(self.already(["-P", "submission/inet/milter_macro_defaults=postwarden_ingress=SUBMISSION587"]))
        self.assertFalse(self.already(["-P", "submission/inet/milter_macro_defaults=postwarden_ingress=SMTP25"]))
        self.assertFalse(self.already(["-P", "smtps/inet/milter_macro_defaults=postwarden_ingress=SUBMISSION465"]))

    def test_removals_and_new_services_always_run(self):
        self.assertFalse(self.already(["-PX", "submission/inet/content_filter"]))
        self.assertFalse(self.already(["-M", "postwarden-cleanup/unix=postwarden-cleanup unix n - y - 0 cleanup"]))


class EnforcementWithLegacyFilters(unittest.TestCase):
    REPORT = {"postfix": {"content_filters": {"smtpd/pass": "filter-external", "smtp/inet": None,
                                              "submission/inet": "filter-local"}}}
    CLEAN = {"postfix": {"content_filters": {"smtpd/pass": None, "submission/inet": None}}}

    def test_enforce_refused_while_filters_reinject(self):
        self.assertEqual(deployment.enforcement_blockers("enforce", self.REPORT, False, False),
                         ["smtpd/pass", "submission/inet"])

    def test_cutover_or_explicit_override_allowed(self):
        self.assertEqual(deployment.enforcement_blockers("enforce", self.REPORT, True, False), [])
        self.assertEqual(deployment.enforcement_blockers("enforce", self.REPORT, False, True), [])

    def test_observe_and_clean_hosts_unaffected(self):
        self.assertEqual(deployment.enforcement_blockers("observe", self.REPORT, False, False), [])
        self.assertEqual(deployment.enforcement_blockers("enforce", self.CLEAN, False, False), [])

    def test_macro_finding_goes_on_to_the_repair(self):
        report = {**self.CLEAN, "daemon_active": True, "socket_present": True, "config": {"valid": True, "mode": "observe"},
                  "findings": [deployment.MACRO_FINDING + "milter_mail_macros lacks {auth_authen}; run configure-postfix to repair",
                               deployment.CHAIN_FINDING + "smtpd_milters; run configure-postfix to repair"]}
        with mock.patch.object(deployment, "stage_postfix", return_value=(Path("/nonexistent"), [], "")) as stage:
            deployment.configure_postfix("observe", report, apply=False, log=lambda m: None)
        stage.assert_called_once()

    def test_configure_refuses_before_touching_anything(self):
        report = {**self.REPORT, "daemon_active": True, "socket_present": True}
        with mock.patch.object(deployment, "stage_postfix") as stage, self.assertRaises(DeploymentError) as ctx:
            deployment.configure_postfix("enforce", report, apply=True, log=lambda m: None)
        stage.assert_not_called()
        self.assertIn("--remove-legacy", str(ctx.exception))


class InstallationRootHygiene(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.root = Path(tempfile.mkdtemp())
        for name in ("src", "bin", "tests", ".agents"):
            (self.root / name).mkdir()
        for name in ("config.toml", "README.md", "CLAUDE.md", "ruleset.xml"):
            (self.root / name).write_text("x")
        (self.root / "AGENTS.md").symlink_to("CLAUDE.md")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.root)

    def test_unmanaged_are_everything_but_release_content_and_config(self):
        names = [p.name for p in deployment.unmanaged_entries(self.root)]
        self.assertEqual(names, [".agents", "AGENTS.md", "CLAUDE.md", "ruleset.xml", "tests"])

    @unittest.skipIf(__import__("os").getuid() == 0, "ownership check needs a non-root test user")
    def test_foreign_ownership_includes_the_root_itself(self):
        foreign = deployment.foreign_owned(self.root)
        self.assertEqual(foreign[0], self.root)
        self.assertIn(self.root / "src", foreign)

    def test_missing_root_is_clean(self):
        self.assertEqual(deployment.unmanaged_entries(self.root / "absent"), [])
        self.assertEqual(deployment.foreign_owned(self.root / "absent"), [])
        self.assertEqual(deployment.writable_by_others(self.root / "absent"), [])

    def test_group_or_world_writable_paths_are_found_and_repaired(self):
        os.chmod(self.root, 0o777)
        os.chmod(self.root / "src", 0o775)
        (self.root / "bin" / "postwarden").write_text("#!/bin/sh\n")
        os.chmod(self.root / "bin" / "postwarden", 0o777)
        os.chmod(self.root / "config.toml", 0o660)
        self.assertEqual(deployment.writable_by_others(self.root),
                         [self.root, self.root / "bin" / "postwarden", self.root / "config.toml", self.root / "src"])
        deployment.normalize_modes(self.root)
        mode = lambda p: p.stat().st_mode & 0o777
        self.assertEqual((mode(self.root), mode(self.root / "src"), mode(self.root / "bin" / "postwarden"),
                          mode(self.root / "README.md")), (0o755, 0o755, 0o755, 0o644))
        self.assertEqual(mode(self.root / "config.toml"), 0o660)


class RemoteTransportFinding(unittest.TestCase):
    def report(self, relaying, configured):
        return {"supported": True, "packages": {name: "1" for name in deployment.RUNTIME_PACKAGES},
                "config": {"present": True, "valid": True, "mynetworks": [], "recipient_delimiter": "",
                           "remote_transports": configured},
                "postfix": {"mynetworks": "", "recipient_delimiter": "", "relaying_transports": relaying,
                            "services": {"smtp/inet": True, "pickup/unix": True}}}

    def test_postfix_relaying_transport_missing_from_config(self):
        findings = deployment._findings(self.report(["relay", "smtp-out"], ["relay", "smtp"]))
        self.assertEqual([f for f in findings if "remote_transports" in f],
                         ["protection.remote_transports lacks Postfix default_transport/relay_transport smtp-out: "
                          "all@ at other domains would be refused"])

    def test_stock_transports_are_covered_by_the_default(self):
        self.assertEqual(deployment._findings(self.report(["relay", "smtp"], ["relay", "smtp"])), [])


class MilterChains(unittest.TestCase):
    def test_postwarden_first_others_kept_in_order(self):
        old = "{ unix:postwarden/policy.sock, default_action=accept }, inet:localhost:8891, { inet:127.0.0.1:12345, default_action=tempfail }"
        self.assertEqual(deployment.with_postwarden(old),
                         "$postwarden_milter, inet:localhost:8891, { inet:127.0.0.1:12345, default_action=tempfail }")
        self.assertEqual(deployment.with_postwarden(""), "$postwarden_milter")
        self.assertEqual(deployment.with_postwarden("$postwarden_milter,inet:localhost:8891", ","),
                         "$postwarden_milter,inet:localhost:8891")

    def test_macro_defaults_merged(self):
        self.assertEqual(deployment.with_ingress_marker("other_flag=YES, postwarden_ingress=UNCLASSIFIED", "SMTP25"),
                         "postwarden_ingress=SMTP25,other_flag=YES")
        self.assertEqual(deployment.with_ingress_marker("", "LOCAL_PICKUP"), "postwarden_ingress=LOCAL_PICKUP")


@unittest.skipUnless(__import__("shutil").which("postconf"), "needs Postfix's postconf")
class RenderAgainstPostconf(unittest.TestCase):
    """Runs the renderer against a scratch Postfix configuration with the local postconf."""
    MASTER = """smtp      inet  n       -       n       -       -       smtpd
submission inet n       -       n       -       -       smtpd
  -o milter_macro_defaults=other_flag=SUBMIT
  -o smtpd_milters=inet:127.0.0.1:8891
smtps     inet  n       -       n       -       -       smtpd
  -o smtpd_milters=
pickup    unix  n       -       n       60      1       pickup
cleanup   unix  n       -       n       -       0       cleanup
"""

    def render(self, main):
        import tempfile
        staging = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, staging)
        (staging / "main.cf").write_text(main)
        (staging / "master.cf").write_text(self.MASTER)
        deployment.render_postfix("enforce", staging, remove_legacy=False)
        return staging

    def test_every_chain_gets_postwarden_and_keeps_others(self):
        staging = self.render("smtpd_milters = inet:127.0.0.1:8891\nnon_smtpd_milters = inet:127.0.0.1:9999\n"
                              "milter_macro_defaults = other_flag=YES\n")
        pc = lambda name: deployment.postconf(name, staging)
        self.assertEqual(pc("smtpd_milters"), "$postwarden_milter, inet:127.0.0.1:8891")
        self.assertEqual(pc("non_smtpd_milters"), "$postwarden_milter, inet:127.0.0.1:9999")
        self.assertIn("default_action=tempfail", pc("postwarden_milter"))
        self.assertEqual(pc("milter_macro_defaults"), "postwarden_ingress=UNCLASSIFIED,other_flag=YES")
        sp = lambda svc, p: deployment.service_param(svc, p, staging)
        self.assertEqual(sp("submission/inet", "smtpd_milters"), "$postwarden_milter,inet:127.0.0.1:8891")
        self.assertEqual(sp("smtps/inet", "smtpd_milters"), "$postwarden_milter")
        self.assertEqual(sp("submission/inet", "milter_macro_defaults"), "postwarden_ingress=SUBMISSION587,other_flag=SUBMIT")
        self.assertEqual(sp("smtp/inet", "milter_macro_defaults"), "postwarden_ingress=SMTP25,other_flag=YES")
        self.assertEqual(sp("postwarden-cleanup/unix", "milter_macro_defaults"), "postwarden_ingress=LOCAL_PICKUP,other_flag=YES")
        self.assertEqual(deployment.chain_gaps(staging), [])

    def test_port_465_service_named_submissions_is_marked(self):
        self.MASTER = self.MASTER.replace("smtps     inet", "submissions inet")
        staging = self.render("")
        sp = lambda svc, p: deployment.service_param(svc, p, staging)
        self.assertEqual(sp("submissions/inet", "milter_macro_defaults"), "postwarden_ingress=SUBMISSION465")
        self.assertEqual(sp("submissions/inet", "smtpd_milters"), "$postwarden_milter")

    def test_minimal_mail_macro_list_gets_sasl_macros(self):
        staging = self.render("milter_mail_macros = i\nmilter_rcpt_macros = i\nmilter_connect_macros = j\n")
        mail = deployment.postconf("milter_mail_macros", staging).split()
        self.assertEqual(mail[0], "i")
        for macro in ("{auth_type}", "{auth_authen}", "{cipher_bits}", "{postwarden_ingress}", "{daemon_port}"):
            self.assertIn(macro, mail)
        self.assertIn("{rcpt_mailer}", deployment.postconf("milter_rcpt_macros", staging).split())
        self.assertEqual(deployment.macro_gaps(staging), [])

    def test_service_macro_overrides_are_merged_idempotently(self):
        import tempfile
        staging = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, staging)
        (staging / "main.cf").write_text("smtpd_milters =\nnon_smtpd_milters =\n")
        (staging / "master.cf").write_text(
            "smtp      inet  n       -       n       -       -       smtpd\n"
            "submission inet n       -       n       -       -       smtpd\n"
            "  -o milter_mail_macros=i\n  -o milter_connect_macros=\n"
            "smtps     inet  n       -       n       -       -       smtpd\n  -o milter_rcpt_macros=i\n"
            "pickup    unix  n       -       n       60      1       pickup\n"
            "cleanup   unix  n       -       n       -       0       cleanup\n"
            "postwarden-cleanup unix n - n - 0 cleanup\n  -o milter_mail_macros=\n")
        before = deployment.macro_gaps(staging)
        self.assertIn("submission/inet/milter_mail_macros lacks {daemon_port} {auth_type} {auth_authen} {cipher_bits} "
                      "{tls_version} {postwarden_ingress}", before)
        self.assertIn("smtps/inet/milter_rcpt_macros lacks {rcpt_mailer}", before)
        self.assertTrue(any(g.startswith("postwarden-cleanup/unix/milter_mail_macros") for g in before))
        self.assertTrue(any(g.startswith("submission/inet/milter_connect_macros") for g in before))
        deployment.render_postfix("enforce", staging, remove_legacy=False)
        sp = lambda svc, p: deployment.split_list(deployment.service_param(svc, p, staging))
        mail = sp("submission/inet", "milter_mail_macros")
        self.assertEqual(mail[0], "i")
        self.assertIn("{auth_authen}", mail)
        self.assertEqual(sp("smtps/inet", "milter_rcpt_macros"), ["i", "{rcpt_mailer}"])
        self.assertIn("{postwarden_ingress}", sp("postwarden-cleanup/unix", "milter_mail_macros"))
        self.assertEqual(deployment.macro_gaps(staging), [])
        again = deployment.render_postfix("enforce", staging, remove_legacy=False)
        self.assertFalse([op for op in again if "macros" in op], again)

    def test_macro_gaps_name_the_stage(self):
        import tempfile
        staging = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, staging)
        (staging / "main.cf").write_text("milter_mail_macros = i {daemon_port} {cipher_bits} {tls_version} {postwarden_ingress}\n")
        (staging / "master.cf").write_text(self.MASTER)
        gaps = deployment.macro_gaps(staging)
        self.assertIn("milter_mail_macros lacks {auth_type} {auth_authen}", gaps)

    def test_shared_local_chain_is_kept(self):
        staging = self.render("smtpd_milters = inet:127.0.0.1:8891\nnon_smtpd_milters = $smtpd_milters\n")
        self.assertEqual(deployment.postconf("non_smtpd_milters", staging), "$smtpd_milters")

    def test_second_run_changes_nothing(self):
        staging = self.render("smtpd_milters = inet:127.0.0.1:8891\n")
        self.assertEqual(deployment.render_postfix("enforce", staging, remove_legacy=False), [])


class _Sandbox(unittest.TestCase):
    """Deployment paths redirected into a temporary tree; commands and ownership changes are recorded, not run."""

    def setUp(self):
        import json
        import tempfile
        self.json = json
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, self.tmp)
        paths = {"ROOT": self.tmp / "etc-postwarden", "BACKUPS": self.tmp / "backups", "LOCK": self.tmp / "lock",
                 "LAUNCHER": self.tmp / "sbin" / "postwarden", "UNIT": self.tmp / "postwarden.service",
                 "POSTFIX_DIR": self.tmp / "postfix", "DEFAULT_CONFIG_PATH": str(self.tmp / "etc-postwarden" / "config.toml")}
        for name, value in paths.items():
            patcher = mock.patch.object(deployment, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        for name in ("ROOT", "POSTFIX_DIR"):
            getattr(deployment, name).mkdir(parents=True)
        self.commands = []
        for target, replacement in (("run", lambda args, **kw: self.commands.append(args) or mock.Mock(stdout="")),
                                    ("service_active", lambda name: True)):
            patcher = mock.patch.object(deployment, target, side_effect=replacement)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch("shutil.chown")
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch("grp.getgrnam", return_value=mock.Mock(gr_gid=0))
        patcher.start()
        self.addCleanup(patcher.stop)


class Rollback(_Sandbox):
    def deployment_with(self, after: bool):
        backup = deployment.BACKUPS / "d1"
        backup.mkdir(parents=True)
        launcher = deployment.LAUNCHER
        launcher.parent.mkdir(parents=True)
        (backup / "postwarden").write_text("#!/bin/sh old\n")
        launcher.write_text("#!/bin/sh new\n")
        os.chmod(launcher, 0o755)
        manifest = {"kind": "install", "before": {str(launcher): {"mode": 0o755, "uid": 0, "gid": 0}}}
        if after:
            manifest["after"] = {str(launcher): deployment.file_state(launcher)}
        (backup / "manifest.json").write_text(self.json.dumps(manifest))
        return launcher

    def test_restores_launcher_executable(self):
        launcher = self.deployment_with(after=True)
        deployment.rollback("d1", apply=True, log=lambda m: None)
        self.assertEqual((launcher.read_text(), launcher.stat().st_mode & 0o777), ("#!/bin/sh old\n", 0o755))

    def test_refuses_files_changed_after_deployment(self):
        launcher = self.deployment_with(after=True)
        launcher.write_text("#!/bin/sh edited by the operator\n")
        with self.assertRaises(DeploymentError):
            deployment.rollback("d1", apply=True, log=lambda m: None)
        self.assertIn("edited", launcher.read_text())
        deployment.rollback("d1", apply=True, log=lambda m: None, force=True)
        self.assertEqual(launcher.read_text(), "#!/bin/sh old\n")

    def test_deployment_without_record_needs_force(self):
        self.deployment_with(after=False)
        with self.assertRaises(DeploymentError):
            deployment.rollback("d1", apply=False, log=lambda m: None)


class ActivationRecovery(_Sandbox):
    def test_failed_reload_restores_files_and_mode(self):
        pf = deployment.POSTFIX_DIR
        for name in ("main.cf", "master.cf"):
            (pf / name).write_text(f"{name} before\n")
        config = Path(deployment.DEFAULT_CONFIG_PATH)
        config.write_text('mode = "observe"\n')
        staging = self.tmp / "staging"
        staging.mkdir()
        for name in ("main.cf", "master.cf"):
            (staging / name).write_text(f"{name} after\n")

        def run(args, **kw):
            self.commands.append(args)
            if args == ["postfix", "reload"] and ["postfix", "reload"] not in self.commands[:-1]:
                raise DeploymentError("reload failed")
            return mock.Mock(stdout="")
        report = {"daemon_active": True, "socket_present": True, "findings": [], "config": {"valid": True, "mode": "observe"},
                  "postfix": {"content_filters": {}, "main_cf_sha256": deployment.sha256(pf / "main.cf"),
                              "master_cf_sha256": deployment.sha256(pf / "master.cf")}}
        with mock.patch.object(deployment, "run", side_effect=run), \
             mock.patch.object(deployment, "stage_postfix", return_value=(staging, ["op"], "diff")):
            with self.assertRaises(DeploymentError) as ctx:
                deployment.configure_postfix("enforce", report, apply=True, log=lambda m: None)
        self.assertIn("previous state was restored", str(ctx.exception))
        self.assertEqual((pf / "main.cf").read_text(), "main.cf before\n")
        self.assertEqual(config.read_text(), 'mode = "observe"\n')
        self.assertEqual(self.commands.count(["systemctl", "restart", "postwarden.service"]), 2)


class ConfigImport(_Sandbox):
    def test_changed_import_restarts_identical_does_not(self):
        config = Path(deployment.DEFAULT_CONFIG_PATH)
        config.write_text("mode = 'observe'\n")
        candidate = self.tmp / "candidate"
        (candidate / "bin").mkdir(parents=True)
        (candidate / "bin" / "postwarden").write_text("x")
        (candidate / "packaging" / "systemd").mkdir(parents=True)
        (candidate / "packaging" / "systemd" / "postwarden.service").write_text("x")
        deployment.LAUNCHER.parent.mkdir(parents=True)
        deployment.LAUNCHER.write_text("x")
        deployment.UNIT.write_text("x")
        report = {"packages": {n: "1" for n in deployment.RUNTIME_PACKAGES}, "service_user": True,
                  "daemon_active": True, "socket_present": True}
        with mock.patch.object(deployment, "tree_digest", return_value="same"), \
             mock.patch.object(deployment, "foreign_owned", return_value=[]), \
             mock.patch.object(deployment, "unmanaged_entries", return_value=[]):
            (deployment.ROOT / "src").mkdir()
            changed = self.tmp / "changed.toml"
            changed.write_text("mode = 'enforce'\n")
            steps = {s.description.split(" ")[0]: s.needed for s in deployment.plan_install(candidate, report, changed).steps}
            self.assertTrue(steps["enable"])
            same = self.tmp / "same.toml"
            same.write_text(config.read_text())
            steps = {s.description.split(" ")[0]: s.needed for s in deployment.plan_install(candidate, report, same).steps}
            self.assertFalse(steps["enable"])
            with mock.patch.object(deployment, "_has_state", return_value=True):
                steps = {s.description.split(" ")[0]: s.needed for s in deployment.plan_install(candidate, report).steps}
                self.assertEqual({k for k, v in steps.items() if v}, set(), steps)
                steps = {s.description.split(" ")[0]: s.needed for s in deployment.plan_install(candidate, report, same).steps}
                self.assertTrue(steps["validate"])
            with mock.patch.object(deployment, "_has_state", return_value=False):
                steps = {s.description.split(" ")[0]: s.needed for s in deployment.plan_install(candidate, report).steps}
                self.assertTrue(steps["create"] and steps["validate"])


class WritableRoot(_Sandbox):
    def test_writable_root_is_secured_even_when_content_is_unchanged(self):
        candidate = self.tmp / "candidate"
        (candidate / "src").mkdir(parents=True)
        (deployment.ROOT / "src").mkdir()
        report = {"packages": {n: "1" for n in deployment.RUNTIME_PACKAGES}, "service_user": True,
                  "daemon_active": True, "socket_present": True}
        with mock.patch.object(deployment, "tree_digest", return_value="same"), \
             mock.patch.object(deployment, "foreign_owned", return_value=[]), \
             mock.patch.object(deployment, "unmanaged_entries", return_value=[]), \
             mock.patch.object(deployment, "_has_state", return_value=True):
            secure = lambda: next(s.needed for s in deployment.plan_install(candidate, report).steps
                                  if s.description.startswith("secure"))
            os.chmod(deployment.ROOT, 0o755)
            self.assertFalse(secure())
            os.chmod(deployment.ROOT, 0o777)
            self.assertTrue(secure())
            os.chmod(deployment.ROOT, 0o755)
            os.chmod(deployment.ROOT / "src", 0o775)
            self.assertTrue(secure())


class ManagedFiles(_Sandbox):
    def test_symlinked_managed_file_refused(self):
        real = self.tmp / "real.toml"
        real.write_text('mode = "observe"\n')
        Path(deployment.DEFAULT_CONFIG_PATH).symlink_to(real)
        with self.assertRaises(DeploymentError) as ctx:
            deployment.refuse_symlinks()
        self.assertIn("is a symlink", str(ctx.exception))
        with self.assertRaises(DeploymentError):
            deployment.backup_file(Path(deployment.DEFAULT_CONFIG_PATH), self.tmp)

    def test_permission_or_owner_change_counts_as_divergence(self):
        target = self.tmp / "file"
        target.write_text("x")
        os.chmod(target, 0o644)
        manifest = {"after": {str(target): deployment.file_state(target)}}
        self.assertEqual(deployment.rollback_divergence(manifest, [target], False), [])
        os.chmod(target, 0o600)
        self.assertEqual(deployment.rollback_divergence(manifest, [target], False), [str(target)])
        os.chmod(target, 0o644)
        with mock.patch.object(deployment, "file_state", return_value={**manifest["after"][str(target)], "uid": 4242}):
            self.assertEqual(deployment.rollback_divergence(manifest, [target], False), [str(target)])


class FirstInstallRollback(_Sandbox):
    def first_install(self):
        backup = deployment.BACKUPS / "d1"
        backup.mkdir(parents=True)
        deployment.LAUNCHER.parent.mkdir(parents=True)
        config = Path(deployment.DEFAULT_CONFIG_PATH)
        for path in (deployment.LAUNCHER, deployment.UNIT, config):
            path.write_text("new")
        manifest = {"kind": "install", "before": {str(p): None for p in (config, deployment.UNIT, deployment.LAUNCHER)},
                    "after": {str(p): deployment.file_state(p) for p in (config, deployment.UNIT, deployment.LAUNCHER)}}
        (backup / "manifest.json").write_text(self.json.dumps(manifest))
        return config

    def test_removes_service_keeps_data(self):
        config = self.first_install()
        logged = []
        with mock.patch("shutil.which", return_value=None):
            deployment.rollback("d1", apply=True, log=logged.append)
        self.assertFalse(deployment.UNIT.exists() or deployment.LAUNCHER.exists())
        self.assertTrue(config.exists())
        self.assertIn(["systemctl", "disable", "--now", "postwarden.service"], self.commands)
        self.assertNotIn(["systemctl", "restart", "postwarden.service"], self.commands)
        self.assertTrue(any(line.startswith("stop and disable postwarden.service; keep") for line in logged))

    def postconf_output(self, main, master):
        def fake_run(args, **kw):
            text = main if "-nx" in args else master if "-Px" in args else ""
            return mock.Mock(stdout=text, returncode=0)
        return fake_run

    def test_refused_while_any_chain_uses_postwarden(self):
        sock = "unix:postwarden/policy.sock"
        cases = {
            "non_smtpd_milters": (f"postwarden_milter = {{ {sock}, default_action=accept }}\nsmtpd_milters =\n"
                                  f"non_smtpd_milters = {{ {sock}, default_action=accept }}\n", ""),
            "submission/inet/smtpd_milters": (f"postwarden_milter = {{ {sock} }}\n",
                                              f"submission/inet/smtpd_milters = {{ {sock} }},inet:127.0.0.1:8891\n"),
        }
        self.first_install()
        for where, (main, master) in cases.items():
            with self.subTest(where=where), mock.patch("shutil.which", return_value="/usr/sbin/postconf"), \
                    mock.patch.object(deployment, "run", side_effect=self.postconf_output(main, master)):
                with self.assertRaises(DeploymentError) as ctx:
                    deployment.rollback("d1", apply=True, log=lambda m: None)
                self.assertIn(where, str(ctx.exception))
                self.assertIn("roll back the configure-postfix deployment first", str(ctx.exception))
        self.assertTrue(deployment.UNIT.exists() and deployment.LAUNCHER.exists())

    def test_detached_postfix_allows_removal(self):
        self.first_install()
        main = "postwarden_milter = { unix:postwarden/policy.sock, default_action=accept }\nsmtpd_milters = inet:127.0.0.1:8891\n"
        calls = []
        fake = self.postconf_output(main, "submission/inet/smtpd_milters = inet:127.0.0.1:8891\n")
        with mock.patch("shutil.which", return_value="/usr/sbin/postconf"), \
             mock.patch.object(deployment, "run", side_effect=lambda a, **k: calls.append(a) or fake(a, **k)):
            deployment.rollback("d1", apply=True, log=lambda m: None)
        self.assertFalse(deployment.UNIT.exists())
        self.assertIn(["systemctl", "disable", "--now", "postwarden.service"], calls)

    def test_attachment_made_before_the_lock_is_refused(self):
        self.first_install()
        detached = "smtpd_milters = inet:127.0.0.1:8891\n"
        attached = "smtpd_milters = unix:postwarden/policy.sock\n"
        state = {"main": detached}
        real_lock = deployment.deployment_lock

        @__import__("contextlib").contextmanager
        def lock_after_attach():
            state["main"] = attached
            with real_lock():
                yield
        with mock.patch("shutil.which", return_value="/usr/sbin/postconf"), \
             mock.patch.object(deployment, "run", side_effect=lambda a, **k: self.postconf_output(state["main"], "")(a, **k)), \
             mock.patch.object(deployment, "deployment_lock", lock_after_attach):
            with self.assertRaises(DeploymentError):
                deployment.rollback("d1", apply=True, log=lambda m: None)
        self.assertTrue(deployment.UNIT.exists())


class ConfigMode(_Sandbox):
    def switch(self, text):
        config = Path(deployment.DEFAULT_CONFIG_PATH)
        config.write_text(text)
        deployment.set_config_mode(config, "enforce")
        return config.read_text()

    def test_every_accepted_spelling(self):
        import tomllib
        for text in ('mode = "observe"\n', "mode = 'observe'\n", '"mode" = "observe"\n', "  mode='observe'  # comment\n",
                     "", "[logging]\nlevel = \"info\"\n", '# header\n\n[protection.addresses."a@b.example"]\nmode = "x"\n'):
            with self.subTest(text=text):
                result = self.switch(text)
                self.assertEqual(tomllib.loads(result)["mode"], "enforce")
                if "[protection" in text:
                    self.assertEqual(tomllib.loads(result)["protection"]["addresses"]["a@b.example"]["mode"], "x")


class InstallRecheck(_Sandbox):
    def test_config_edited_between_plan_and_apply_is_refused(self):
        config = Path(deployment.DEFAULT_CONFIG_PATH)
        config.write_text('mode = "observe"\n')

        def plan_then_edit(*args, **kw):
            config.write_text('mode = "enforce"\n')
            plan = deployment.Plan()
            plan.add("change something", lambda: None)
            return plan
        with mock.patch.object(deployment, "plan_install", side_effect=plan_then_edit):
            with self.assertRaises(DeploymentError) as ctx:
                deployment.install(self.tmp, {}, apply=True, log=lambda m: None)
        self.assertIn("changed since the plan was made", str(ctx.exception))
        self.assertFalse(deployment.BACKUPS.exists() and any(deployment.BACKUPS.iterdir()))


class ReleaseManifest(_Sandbox):
    def test_manifest_is_managed_and_removed_when_source_lacks_it(self):
        self.assertIn("MANIFEST.sha256", deployment.APP_FILES)
        deployment.ROOT.mkdir(parents=True, exist_ok=True)
        (deployment.ROOT / "MANIFEST.sha256").write_text("old\n")
        self.assertNotIn(deployment.ROOT / "MANIFEST.sha256", deployment.unmanaged_entries(deployment.ROOT))

    def test_build_script_is_not_installed(self):
        candidate = self.tmp / "candidate"
        (candidate / "scripts").mkdir(parents=True)
        (candidate / "scripts" / "install.py").write_text("x")
        before = deployment.tree_digest(candidate)
        (candidate / "scripts" / "build-release.py").write_text("y")
        self.assertEqual(deployment.tree_digest(candidate), before)


class NoOpRuns(_Sandbox):
    def test_install_with_nothing_to_do_records_no_deployment(self):
        logged = []
        with mock.patch.object(deployment, "plan_install", return_value=deployment.Plan()):
            self.assertIsNone(deployment.install(self.tmp, {}, apply=True, log=logged.append))
        self.assertIn("nothing to change; no deployment recorded", logged)
        self.assertFalse(deployment.BACKUPS.exists() and any(deployment.BACKUPS.iterdir()))

    def test_configure_postfix_with_nothing_to_do_records_no_deployment(self):
        staging = self.tmp / "staging"
        staging.mkdir()
        report = {"config": {"mode": "enforce", "valid": True}, "findings": [], "daemon_active": True, "socket_present": True}
        logged = []
        with mock.patch.object(deployment, "enforcement_blockers", return_value=[]), \
             mock.patch.object(deployment, "stage_postfix", return_value=(staging, [], "")):
            self.assertIsNone(deployment.configure_postfix("enforce", report, apply=True, log=logged.append))
        self.assertIn("nothing to change; no deployment recorded", logged)
        self.assertFalse(deployment.BACKUPS.exists() and any(deployment.BACKUPS.iterdir()))
