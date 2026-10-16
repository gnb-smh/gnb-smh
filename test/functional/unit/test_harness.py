"""Harness regressions: real runner/wait code, deterministic process/node fixtures."""

import contextlib
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import feature_partition_heal as partition
import test_runner as runner
from test_framework import util


class Clock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        assert seconds >= 0
        self.now += seconds


class RunnerTests(unittest.TestCase):
    def run_runner(self, codes, *options):
        """Keep main, Job.poll and Job.finish real; only external work is fake."""
        clock = Clock()
        processes = []
        for code in codes:
            proc = mock.Mock(returncode=code)
            proc.poll.return_value = code
            processes.append(proc)
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as root, contextlib.ExitStack() as stack:
            argv = ["test_runner.py", "--jobs", "2", "--no-build",
                    "--cachedir", os.path.join(root, "cache"),
                    "--tmpdir", os.path.join(root, "run"),
                    *options, *runner.ALL_TESTS[:len(codes)]]
            stack.enter_context(mock.patch.object(sys, "argv", argv))
            stack.enter_context(mock.patch.object(runner.binaries, "resolve", return_value={"gnb": "/fake/gnb"}))
            stack.enter_context(mock.patch.object(runner, "Cache"))
            popen = stack.enter_context(mock.patch.object(runner.subprocess, "Popen", side_effect=processes))
            stack.enter_context(mock.patch.object(runner, "kill_strays", return_value=0))
            stack.enter_context(mock.patch.object(runner.time, "monotonic", clock.monotonic))
            stack.enter_context(mock.patch.object(runner.time, "sleep", clock.sleep))
            stack.enter_context(contextlib.redirect_stdout(output))
            result = runner.main()
            self.assertEqual(popen.call_count, len(codes), "every selected scenario must be launched")
        return result, output.getvalue()

    def test_all_skipped_is_not_a_successful_ci_run(self):
        status, output = self.run_runner([77, 77])
        self.assertEqual(status, 1, output)

    def test_mixed_pass_skip_is_not_complete(self):
        status, output = self.run_runner([0, 77])
        self.assertEqual(status, 1, output)

    def test_skip_is_reported_separately_from_pass(self):
        _, output = self.run_runner([0, 77])
        self.assertIn("1 passed, 1 skipped, 0 failed", output)

    def test_all_passed_is_success(self):
        status, output = self.run_runner([0, 0])
        self.assertEqual(status, 0, output)

    def test_actual_failure_is_failure(self):
        status, output = self.run_runner([0, 1])
        self.assertEqual(status, 1, output)

    def test_explicit_ci_mode_rejects_skips(self):
        status, output = self.run_runner([77, 77], "--ci")
        self.assertEqual(status, 1, output)
        self.assertIn("0 passed, 2 skipped, 0 failed", output)

    def test_local_skips_are_explicit_and_not_counted_as_passed(self):
        for codes, summary in [([0, 77], "1 passed, 1 skipped, 0 failed"),
                               ([77, 77], "0 passed, 2 skipped, 0 failed")]:
            with self.subTest(codes=codes):
                status, output = self.run_runner(codes, "--allow-skips")
                self.assertEqual(status, 0, output)
                self.assertIn(summary, output)
                self.assertIn("skips explicitly allowed", output)

    def test_local_skip_mode_never_hides_failure(self):
        status, output = self.run_runner([77, 1], "--allow-skips")
        self.assertEqual(status, 1, output)
        self.assertIn("0 passed, 1 skipped, 1 failed", output)

    def test_ci_and_local_skip_modes_cannot_be_combined(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as result:
            self.run_runner([77], "--ci", "--allow-skips")
        self.assertEqual(result.exception.code, 2)


class HealObserved(Exception):
    """Stop after the real scenario has accepted convergence and checked its tips."""


class Node:
    def __init__(self, world, index):
        self.world, self.index = world, index
        self.p2p_addr = f"/ip4/127.0.0.1/tcp/{20000 + index}"
        self.blocks = []

    def generate(self, count, address):
        prefix = "common" if count == 1 else "a" if self.index == 0 else "b"
        blocks = [f"{prefix}{i}" for i in range(count)]
        recipients = self.world.nodes if count == 1 else self.world.nodes[:2] if self.index == 0 else [self]
        for node in recipients:
            node.blocks += blocks
        return blocks

    def restart(self, peers):
        self.world.healing = bool(peers)

    def cli_send(self, *args):
        return "payment"

    def mempool(self):
        return ["payment"]

    def height(self):
        return len(self.blocks)

    def peer_id(self):
        return f"peer{self.index}"

    def sees_peer(self, peer_id):
        ready = self.world.peer_ready.get((self.index, int(peer_id[-1])), 0)
        return self.world.clock.now >= ready

    def tip(self):
        if self.world.healing:
            if self.world.slow_tip:
                delay, self.world.slow_tip = self.world.slow_tip, 0
                self.world.clock.sleep(delay)
            if self.world.clock.now >= self.world.converge_at:
                return "b3"
        return self.blocks[-1]

    def valid_tips(self):
        if self.world.healing and self.world.clock.now >= self.world.converge_at:
            return ["a1", "b3"]
        return [self.tip()]

    def has_block(self, block):
        return block in self.blocks or self.world.healing


class Scenario(partition.PartitionHealTest):
    def __init__(self, clock, peer_ready, converge_at, slow_tip=0):
        super().__init__()
        self.clock, self.peer_ready = clock, peer_ready
        self.converge_at, self.slow_tip = converge_at, slow_tip
        self.healing = False
        self.chain_info = {"height": 0, "wallet_address": "sender"}
        self.nodes = [Node(self, i) for i in range(3)]

    def wallet_copy(self):
        return "fake-wallet"

    def tx_status(self, node, txid):
        return "a0"

    def assert_same_chain_state(self, addresses):
        raise HealObserved


class DeadlineTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(util.time, "monotonic", self.clock.monotonic).start()
        mock.patch.object(util.time, "sleep", self.clock.sleep).start()
        mock.patch.object(util, "TIMEOUT_FACTOR", 1.0).start()

    def test_late_peer_connection_cannot_pass_heal(self):
        scenario = Scenario(self.clock, {(2, 0): 31}, 31)
        with self.assertRaises(util.AssertionFailure):
            try:
                scenario.run_test()
            except HealObserved:
                self.fail(f"real partition scenario accepted convergence at {self.clock.now}s")
        self.assertLessEqual(self.clock.now, 30)

    def test_peer_waits_and_settle_share_the_heal_deadline(self):
        scenario = Scenario(self.clock, {(2, 0): 10, (0, 2): 20, (2, 1): 29, (1, 2): 29}, 29)
        with self.assertRaises(util.AssertionFailure):
            try:
                scenario.run_test()
            except HealObserved:
                self.fail(f"settling escaped the heal deadline: {self.clock.now}s")
        self.assertLessEqual(self.clock.now, 30)

    def test_slow_successful_sync_observation_cannot_pass_late(self):
        scenario = Scenario(self.clock, {}, 31, slow_tip=29)
        with self.assertRaises(util.AssertionFailure):
            try:
                scenario.run_test()
            except HealObserved:
                self.fail(f"late RPC result accepted at {self.clock.now}s")

    def test_convergence_before_deadline_is_accepted(self):
        scenario = Scenario(self.clock, {(2, 0): 4, (2, 1): 7}, 10)
        with self.assertRaises(HealObserved):
            scenario.run_test()
        self.assertEqual(self.clock.now, 10)

    def test_timeout_factor_scales_the_shared_deadline_once(self):
        with mock.patch.object(util, "TIMEOUT_FACTOR", 2):
            scenario = Scenario(self.clock, {(2, 0): 61}, 61)
            with self.assertRaises(util.AssertionFailure):
                scenario.run_test()
        self.assertEqual(self.clock.now, 60)

    def test_explicit_slow_machine_factor_accepts_within_scaled_deadline(self):
        with mock.patch.object(util, "TIMEOUT_FACTOR", 2):
            scenario = Scenario(self.clock, {(2, 0): 40}, 45)
            with self.assertRaises(HealObserved):
                scenario.run_test()
        self.assertEqual(self.clock.now, 45)

    def test_absolute_deadline_is_not_reset_for_another_wait(self):
        deadline = self.clock.now + 30
        util.wait_until(lambda: self.clock.now >= 20, deadline=deadline)
        with self.assertRaises(util.AssertionFailure):
            util.wait_until(lambda: self.clock.now >= 31, deadline=deadline)
        self.assertEqual(self.clock.now, 30)

    def test_expired_deadline_does_not_start_a_predicate(self):
        predicate = mock.Mock(return_value=True)
        with self.assertRaises(util.AssertionFailure):
            util.wait_until(predicate, deadline=self.clock.now)
        predicate.assert_not_called()

    def test_relative_timeout_still_scales(self):
        with mock.patch.object(util, "TIMEOUT_FACTOR", 2):
            with self.assertRaises(util.AssertionFailure):
                util.wait_until(lambda: False, timeout=3)
        self.assertEqual(self.clock.now, 6)

    def test_predicate_exceptions_are_reported_and_assertions_propagate(self):
        with self.assertRaisesRegex(util.AssertionFailure, "offline"):
            util.wait_until(mock.Mock(side_effect=OSError("offline")), timeout=1)
        with self.assertRaisesRegex(AssertionError, "invariant"):
            util.wait_until(mock.Mock(side_effect=AssertionError("invariant")))

    def test_real_scenario_still_requires_thirty_seconds(self):
        self.assertEqual(partition.HEAL_TIMEOUT, 30)

    def test_wait_does_not_accept_a_predicate_returning_after_timeout(self):
        def slow_success():
            self.clock.sleep(31)
            return True
        with self.assertRaises(util.AssertionFailure):
            util.wait_until(slow_success, timeout=30)

    def test_poll_sleep_is_bounded_by_remaining_time(self):
        with self.assertRaises(util.AssertionFailure):
            util.wait_until(lambda: False, timeout=0.1, interval=0.25)
        self.assertLessEqual(self.clock.now, 0.1)


if __name__ == "__main__":
    unittest.main()
