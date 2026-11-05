import errno
import io
import socket
import unittest

from samma_finding import netutil


def fake_getaddrinfo(host, port, family=0, socktype=0, proto=0, flags=0):
    """A dual-stack host: AAAA first, then A, with a duplicate the resolver may return."""
    return [
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::10", port or 0, 0, 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", port or 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", port or 0)),
    ]


class FakeSocket(object):
    """Accepts only the families listed in ``accept``."""

    def __init__(self, family, socktype, accept, log):
        self.family = family
        self.accept = accept
        self.log = log
        self.timeout = None

    def settimeout(self, value):
        self.timeout = value

    def connect(self, sockaddr):
        self.log.append((self.family, sockaddr))
        if self.family not in self.accept:
            raise ConnectionRefusedError(111, "Connection refused")

    def connect_ex(self, sockaddr):
        self.log.append((self.family, sockaddr))
        return 0 if self.family in self.accept else 111

    def close(self):
        pass


def factory(accept, log):
    return lambda family, socktype: FakeSocket(family, socktype, accept, log)


class ErrorSocket(object):
    """Raises the error given for its family, or accepts."""

    def __init__(self, family, errors):
        self.family = family
        self.errors = errors

    def settimeout(self, value):
        pass

    def connect(self, sockaddr):
        error = self.errors.get(self.family)
        if error is not None:
            raise error

    def close(self):
        pass


def errors_by_family(errors):
    return lambda family, socktype: ErrorSocket(family, errors)


class FakeClock(object):
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


class Closable(object):
    closed = False

    def close(self):
        self.closed = True


NATS_ENV = {"NATS_ENABLED": "True", "NATS_URL": "nats://scanner:s3cret@nats:4222"}


class AwaitEgressTest(unittest.TestCase):
    def test_nothing_to_probe_without_nats(self):
        for env in ({}, {"NATS_ENABLED": "False", "NATS_URL": "nats://nats:4222"},
                    {"NATS_ENABLED": "True", "NATS_URL": ""}, {"NATS_ENABLED": "True", "NATS_URL": "nats://nats:notaport"}):
            with self.subTest(env=env):
                self.assertIsNone(netutil.await_egress(env, connect=self.fail_connect))

    def fail_connect(self, *args):
        raise AssertionError("must not connect")

    def test_nats_address_from_the_url(self):
        self.assertEqual(netutil.nats_address(NATS_ENV), ("nats", 4222))
        self.assertEqual(netutil.nats_address({"NATS_ENABLED": "true", "NATS_URL": "nats://broker.example"}),
                         ("broker.example", 4222))

    def test_ready_at_once_does_not_wait_or_log(self):
        clock, err, sock = FakeClock(), io.StringIO(), Closable()
        result = netutil.await_egress(NATS_ENV, connect=lambda h, p, t: (sock, None),
                                      sleep=clock.sleep, clock=clock, stderr=err)
        self.assertTrue(result.ready)
        self.assertEqual((result.attempts, clock.sleeps, err.getvalue()), (1, [], ""))
        self.assertTrue(sock.closed)

    def test_retries_until_the_policy_lets_the_pod_out(self):
        clock, err = FakeClock(), io.StringIO()
        outcomes = [ConnectionRefusedError(errno.ECONNREFUSED, "Connection refused"),
                    socket.gaierror(-3, "Temporary failure in name resolution"),
                    (Closable(), None)]
        seen = []

        def connect(host, port, timeout):
            seen.append((host, port))
            outcome = outcomes.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

        result = netutil.await_egress(NATS_ENV, connect=connect, sleep=clock.sleep, clock=clock, stderr=err)
        self.assertTrue(result.ready)
        self.assertEqual(result.attempts, 3)
        self.assertEqual(seen, [("nats", 4222)] * 3)
        self.assertEqual(clock.sleeps, [0.1, 0.2])
        self.assertIn("network ready after 0.30s (3 attempts)", err.getvalue())

    def test_gives_up_after_the_budget_and_lets_the_scan_go_on(self):
        clock, err = FakeClock(), io.StringIO()

        def refused(host, port, timeout):
            raise ConnectionRefusedError(errno.ECONNREFUSED, "Connection refused")

        result = netutil.await_egress(dict(NATS_ENV, SAMMA_EGRESS_WAIT_SECONDS="2"), connect=refused,
                                      sleep=clock.sleep, clock=clock, stderr=err)
        self.assertFalse(result.ready)
        self.assertAlmostEqual(clock.now, 2.0)
        self.assertIsInstance(result.error, ConnectionRefusedError)
        self.assertIn("not reachable after 2.0s (Connection refused); scanning anyway", err.getvalue())

    def test_budget_from_the_environment(self):
        self.assertIsNone(netutil.await_egress(dict(NATS_ENV, SAMMA_EGRESS_WAIT_SECONDS="0"), connect=self.fail_connect))
        clock = FakeClock()

        def refused(host, port, timeout):
            raise ConnectionRefusedError(errno.ECONNREFUSED, "Connection refused")

        netutil.await_egress(dict(NATS_ENV, SAMMA_EGRESS_WAIT_SECONDS="soon"), connect=refused,
                             sleep=clock.sleep, clock=clock, stderr=io.StringIO())
        self.assertAlmostEqual(clock.now, netutil.DEFAULT_EGRESS_WAIT)


class ResolveTest(unittest.TestCase):
    def test_dual_stack_hostname_keeps_both_families_and_order(self):
        addresses = netutil.resolve("dual.example", 443, getaddrinfo=fake_getaddrinfo)
        self.assertEqual([a.family_name for a in addresses], ["ipv6", "ipv4"])
        self.assertEqual([a.address for a in addresses], ["2001:db8::10", "192.0.2.10"])
        self.assertEqual(addresses[0].sockaddr, ("2001:db8::10", 443, 0, 0))
        self.assertEqual(addresses[0].describe(), {"address": "2001:db8::10", "family": "ipv6"})

    def test_ipv6_literal_resolves_without_dns(self):
        addresses = netutil.resolve("2001:db8::1", 443)
        self.assertEqual(len(addresses), 1)
        self.assertEqual(addresses[0].family, socket.AF_INET6)
        self.assertEqual(addresses[0].sockaddr[:2], ("2001:db8::1", 443))

    def test_ipv4_literal_resolves_without_dns(self):
        addresses = netutil.resolve("192.0.2.1", 80)
        self.assertEqual([(a.family, a.address) for a in addresses], [(socket.AF_INET, "192.0.2.1")])

    def test_unknown_name_raises_gaierror(self):
        def no_such(*args, **kwargs):
            raise socket.gaierror(-2, "Name or service not known")
        with self.assertRaises(socket.gaierror):
            netutil.resolve("nope.invalid", 80, getaddrinfo=no_such)

    def test_only_unknown_families_raises_gaierror(self):
        def odd(*args, **kwargs):
            return [(socket.AF_UNIX, socket.SOCK_STREAM, 0, "", "/tmp/x")]
        with self.assertRaises(socket.gaierror):
            netutil.resolve("x", 80, getaddrinfo=odd)

    def test_with_port_keeps_scope_id(self):
        resolved = netutil.ResolvedAddress(socket.AF_INET6, "fe80::1", ("fe80::1", 0, 0, 3))
        self.assertEqual(netutil.with_port(resolved, 22).sockaddr, ("fe80::1", 22, 0, 3))


class ConnectTest(unittest.TestCase):
    def setUp(self):
        self.addresses = netutil.resolve("dual.example", None, getaddrinfo=fake_getaddrinfo)

    def test_falls_back_from_ipv6_to_ipv4(self):
        log = []
        sock, used = netutil.connect_any("dual.example", 443, 2.0, addresses=self.addresses,
                                         socket_factory=factory({socket.AF_INET}, log))
        self.assertEqual(used.family, socket.AF_INET)
        self.assertEqual(used.sockaddr, ("192.0.2.10", 443))
        self.assertEqual(log, [(socket.AF_INET6, ("2001:db8::10", 443, 0, 0)),
                               (socket.AF_INET, ("192.0.2.10", 443))])
        self.assertEqual(sock.timeout, 2.0)

    def test_ipv6_first_when_it_accepts(self):
        log = []
        _sock, used = netutil.connect_any("dual.example", 443, 1, addresses=self.addresses,
                                          socket_factory=factory({socket.AF_INET6, socket.AF_INET}, log))
        self.assertEqual(used.family_name, "ipv6")
        self.assertEqual(len(log), 1)

    def test_all_refused_raises_the_last_error(self):
        with self.assertRaises(ConnectionRefusedError):
            netutil.connect_any("dual.example", 443, 1, addresses=self.addresses,
                                socket_factory=factory(set(), []))

    def test_unroutable_ipv6_never_hides_the_ipv4_answer(self):
        # ankra-dev 2026-11-05: an IPv4-only pod network, a dual-stack host
        # whose IPv4 address refuses port 22. Either resolver order must give
        # the refusal, not "Network is unreachable".
        v6, v4 = self.addresses
        for order in ([v4, v6], [v6, v4]):
            with self.subTest(order=[a.family_name for a in order]):
                with self.assertRaises(ConnectionRefusedError) as ctx:
                    netutil.connect_any("dual.example", 22, 1, addresses=order,
                                        socket_factory=errors_by_family({
                                            socket.AF_INET: ConnectionRefusedError(errno.ECONNREFUSED, "Connection refused"),
                                            socket.AF_INET6: OSError(errno.ENETUNREACH, "Network is unreachable"),
                                        }))
                exc = ctx.exception
                self.assertEqual(exc.errno, errno.ECONNREFUSED)
                self.assertIn("ipv4 192.0.2.10: Connection refused", str(exc))
                self.assertIn("ipv6 2001:db8::10: Network is unreachable", str(exc))
                self.assertIn("port 22", str(exc))
                self.assertEqual(len(exc.attempts), 2)

    def test_only_unroutable_addresses_raise_unreachable(self):
        with self.assertRaises(OSError) as ctx:
            netutil.connect_any("v6only.example", 443, 1, addresses=[self.addresses[0]],
                                socket_factory=errors_by_family({
                                    socket.AF_INET6: OSError(errno.ENETUNREACH, "Network is unreachable")}))
        self.assertEqual(ctx.exception.errno, errno.ENETUNREACH)

    def test_one_address_keeps_its_own_error(self):
        original = ConnectionRefusedError(errno.ECONNREFUSED, "Connection refused")
        with self.assertRaises(ConnectionRefusedError) as ctx:
            netutil.connect_any("v4.example", 22, 1, addresses=[self.addresses[1]],
                                socket_factory=errors_by_family({socket.AF_INET: original}))
        self.assertIs(ctx.exception, original)

    def test_timeouts_keep_their_class(self):
        v6, v4 = self.addresses
        with self.assertRaises(TimeoutError):
            netutil.connect_any("dual.example", 443, 1, addresses=[v4, v6],
                                socket_factory=errors_by_family({
                                    socket.AF_INET: socket.timeout("timed out"),
                                    socket.AF_INET6: OSError(errno.ENETUNREACH, "Network is unreachable")}))

    def test_create_connection_goes_through_connect_any(self):
        calls = []

        def connect(host, port, timeout):
            calls.append((host, port, timeout))
            return "sock", None

        self.assertEqual(netutil.create_connection(("example.com", 443), 5, None, connect=connect), "sock")
        self.assertEqual(calls, [("example.com", 443, 5)])

    def test_http_classes_connect_with_connect_any(self):
        self.assertIs(netutil.HTTPConnection("example.com", 80)._create_connection, netutil.create_connection)
        self.assertIs(netutil.HTTPSConnection("example.com", 443)._create_connection, netutil.create_connection)

    def test_probe_port_per_address(self):
        v6, v4 = self.addresses
        log = []
        self.assertFalse(netutil.probe_port(v6, 22, 1, socket_factory=factory({socket.AF_INET}, log)))
        self.assertTrue(netutil.probe_port(v4, 22, 1, socket_factory=factory({socket.AF_INET}, log)))
        self.assertEqual(log[1], (socket.AF_INET, ("192.0.2.10", 22)))
