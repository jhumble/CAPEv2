import json
import logging
import os
import socket
import subprocess
import re

from contextlib import closing
from threading import Thread

from lib.cuckoo.common.abstracts import Auxiliary
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.core.rooter import rooter

log = logging.getLogger(__name__)

polarproxy = Config("polarproxy")
routing = Config("routing")

class PolarProxy(Auxiliary):
    """Module for generating PCAP with PolarProxy."""

    def __init__(self):
        Auxiliary.__init__(self)
        Thread.__init__(self)
        log.info("PolarProxy module loaded")
        self.polarproxy_thread = None

    def start(self):
        """Start PolarProxy in a separate thread."""

        self.polarproxy_thread = PolarProxyThread(self.task, self.machine)
        self.polarproxy_thread.start()
        return True

    def stop(self):
        """Stop PolarProxy capture thread."""
        if self.polarproxy_thread:
            self.polarproxy_thread.stop()


class PolarProxyThread(Thread):
    """Thread responsible for control PolarProxy service for each analysis."""

    def __init__(self, task, machine):
        Thread.__init__(self)
        self.task = task
        self.storage_dir = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(self.task.id), "polarproxy")
        self.machine = machine
        self.proc = None
        self.log_file = None
        self.pcap = None
        self.do_run = True
        self.host_ip = polarproxy.cfg.get("host")
        self.host_iface = polarproxy.cfg.get("interface")
        self.polar_path = polarproxy.cfg.get("bin")
        self.cert = polarproxy.cfg.get("cert")
        self.password = polarproxy.cfg.get("password")
        self.bypass_domains = polarproxy.cfg.get("bypass_list")
        self.block_domains = polarproxy.cfg.get("block_list")
        self.ruleset = os.path.join(self.storage_dir, "ruleset.json")

        # LOCAL PATCH: intercept a LIST of ports, not one.
        #
        # Upstream hardcodes a single port (443, overridable per task with
        # tlsport=N). Malware C2 is routinely on a non-standard TLS port --
        # AsyncRAT/VenomRAT/Quasar/Pure-family builders default to 4449, 6606,
        # 7707, 8808 and friends. Those flows were passed through untouched and
        # never reached the decrypted capture, and the failure is SILENT: the
        # task reports normally, options still say polarproxy=1, and tls.pcap
        # exists and is non-empty (full of Windows background noise), so every
        # surface-level check says interception worked. An analyst reading only
        # tls.pcap concludes "no C2 activity" -- the exact wrong conclusion.
        # Measured on task 113: 825 packets to the C2 on :4449 in dump.pcap, 0
        # in tls.pcap.
        #
        # Intercepting ALL ports is NOT an option here: PolarProxy's
        # `--nontls allow` only works when the target host is explicit
        # (--httpconnect/--socks/--haproxy). In transparent -p mode the target
        # comes from SNI, so non-TLS sessions hit the default action, `block`,
        # and redirecting everything would kill plain HTTP, SMB and friends.
        # Hence an explicit list, tunable in conf/polarproxy.conf without
        # re-patching this file.
        self.tlsports = self._configured_ports()
        # One listener per intercepted port; PolarProxy accepts repeated -p.
        self.listen_ports = {}
        for port in self.tlsports:
            lp = self._get_unused_port()
            if lp:
                self.listen_ports[port] = lp
        # Kept for compatibility with the rest of the module.
        self.tlsport = self.tlsports[0] if self.tlsports else 443
        self.listen_port = self.listen_ports.get(self.tlsport)

    # Default stays 443, matching upstream. Widening it costs a listener and a
    # REDIRECT rule per port on every analysis, for ports most samples never
    # touch. The workflow is instead: run, see C2 on some port in dump.pcap,
    # resubmit with options=tlsport=443,<port>.
    DEFAULT_TLS_PORTS = (443,)

    def _configured_ports(self):
        """Ports to intercept: conf/polarproxy.conf `tlsports`, else the default set."""
        raw = polarproxy.cfg.get("tlsports")
        if not raw:
            return list(self.DEFAULT_TLS_PORTS)
        ports = []
        for chunk in str(raw).split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            try:
                n = int(chunk)
            except ValueError:
                log.warning("polarproxy.conf: ignoring non-numeric tlsports entry %r", chunk)
                continue
            if 1 <= n <= 65535 and n not in ports:
                ports.append(n)
        return ports or list(self.DEFAULT_TLS_PORTS)

    def _get_unused_port(self) -> int | None:
        """Return the first unused TCP port from the set."""
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.bind(("", 0))
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            return s.getsockname()[1]
        return None

    def generate_ruleset(self):
        """Generate PolarProxy TLS firewall ruleset JSON file."""
        ruleset_json = {
            "name": "PolarProxy ruleset for CAPEv2.",
            "version": "1.0",
            "description": "A curated ruleset generated on the fly to block/bypass specific domain patterns AND handle termination proxying to InetSim.",
            "rules": [],
        }
        if self.task.route == "inetsim":
            # It does not appear feasible to redirect packets from client destined for port 443 to
            # a local service listening on port XYZ _AND_ have iptables DNAT that same packet to
            # inetsim. After PREROUTING to localhost:XYZ, iptables briefly "loses track" of the
            # packet, so when it comes back out of PolarProxy and hits the OUTPUT table, the
            # source IP is localhost and iptables cannot distinguish if the packet came from the
            # host or has been proxied. This means the packet also cannot be masqueraded because
            # it has not been forwarded, it has been proxied. Redirecting all 443 from localhost
            # to inetsim would be very unpleasant for the hosts HTTPS stack. So, PolarProxy is
            # made a termination proxy and forwards the decrypted HTTP to inetsim.
            #
            # Using this ruleset approach instead of `--terminate --connect` is safer because the
            # default action type "inspect" will clash with these flags and try to decrypt already
            # decrypted traffic.
            ruleset_json["default"] = {
                "action": {"type": "terminate", "target": f"{routing.inetsim.server}:80"},
                "description": "Terminate TLS and forward to InetSim server.",
            }
        else:
            ruleset_json["default"] = {
                "action": {"type": "inspect"},
                "description": "Inspect any traffic that is not bypassed or blocked.",
            }

        # If bypass domains are specified in polarproxy.conf, add a block rule for each domain within.
        if self.block_domains:
            with open(self.block_domains, "r") as fh:
                domain_regexes = [line.strip() for line in fh.readlines() if line.strip()]
            for domain_regex in domain_regexes:
                ruleset_json["rules"].append(
                    {"active": True, "match": {"type": "domain_regex", "expression": domain_regex}, "action": {"type": "block"}}
                )

        # If bypass domains are specified in polarproxy.conf, add a bypass rule for each domain within.
        if self.bypass_domains:
            with open(self.bypass_domains, "r") as fh:
                domain_regexes = [line.strip() for line in fh.readlines() if line.strip()]
            for domain_regex in domain_regexes:
                ruleset_json["rules"].append(
                    {"active": True, "match": {"type": "domain_regex", "expression": domain_regex}, "action": {"type": "bypass"}}
                )

        # LOCAL PATCH: let no-SNI sessions through instead of killing them.
        #
        # PolarProxy in transparent mode derives the upstream target from SNI.
        # A ClientHello with no SNI -- which is what you get from malware that
        # connects to a hardcoded IP -- leaves it with nowhere to forward, so it
        # logs NoSniException and CLOSES the connection. CAPE passes
        # `--nosni nosni.example.org` for exactly this case, but PolarProxy warns
        # "command line argument --ruleset overrides --nosni" and CAPE always
        # generates a ruleset, so that flag never takes effect.
        #
        # The consequence is worse than not intercepting: the C2 connection is
        # actively broken, so the sample cannot beacon at all and the analysis is
        # a false negative. Measured on task 118 -- eight consecutive
        # "Closing connection without SNI" / "Failed to establish internal TLS
        # session" against a PureHVNC C2 on :4449.
        #
        # A null expression matches sessions with no SNI (netresec TlsFirewall
        # docs). Bypassing them restores pass-through: the flow is NOT decrypted
        # -- it cannot be, there is no IP match type and no target to connect to
        # -- but it reaches the C2, so behaviour is preserved and the handshake,
        # certificate and JA3/JA3S are still in dump.pcap.
        ruleset_json["rules"].append(
            {
                "active": True,
                "match": {"type": "domain", "expression": None},
                "action": {"type": "bypass"},
                "description": "No SNI: cannot determine an upstream target, so pass through "
                               "undecrypted rather than closing the session.",
            }
        )

        with open(self.ruleset, "w") as fh:
            json.dump(ruleset_json, fh, indent=2)

    def run(self):
        if "polarproxy=" not in self.task.options:
            log.info("Exiting polarproxy. No parameter received.")
            return

        if self.do_run:
            if not self.listen_port:
                log.exception("PolarProxy failed to find an available bind port. Bailing...")
                return

            # Per-task override. Now accepts a comma-separated list; a single
            # value still behaves exactly as before.
            if "tlsport" in self.task.options:
                match = re.search(r"tlsport=([\d,]+)", self.task.options)
                if not match:
                    log.warning("Failed to parse 'tlsport' out of options (%s). Keeping %s.", self.task.options, self.tlsports)
                else:
                    wanted = []
                    for chunk in match.group(1).split(","):
                        chunk = chunk.strip()
                        if chunk.isdigit() and 1 <= int(chunk) <= 65535 and int(chunk) not in wanted:
                            wanted.append(int(chunk))
                    if wanted:
                        self.tlsports = wanted
                        self.listen_ports = {}
                        for port in self.tlsports:
                            lp = self._get_unused_port()
                            if lp:
                                self.listen_ports[port] = lp
                        self.tlsport = self.tlsports[0]
                        self.listen_port = self.listen_ports.get(self.tlsport)

            if not self.listen_ports:
                log.error("PolarProxy: no listener ports available. Bailing...")
                return

            # One REDIRECT per intercepted port.
            self.enabled_ports = []
            for port, lp in sorted(self.listen_ports.items()):
                try:
                    rooter("polarproxy_enable", self.host_iface, self.machine.ip, str(port), str(lp))
                    self.enabled_ports.append((port, lp))
                except subprocess.CalledProcessError as e:
                    log.exception("Failed to add firewall rule for port %s: %s", port, e)
            if not self.enabled_ports:
                log.error("PolarProxy: no firewall rules installed. Bailing...")
                return
            log.info("PolarProxy intercepting TCP %s", ",".join(str(p) for p, _ in self.enabled_ports))

            log.info("Starting PolarProxy process")

            # Create directory to store pcap and logs.
            os.makedirs(self.storage_dir, exist_ok=True)

            # Create ruleset file to bypass/block domains AND terminate proxy to InetSim if applicable
            self.generate_ruleset()

            # Specify where to dump decrypted traffic PCAP
            self.pcap = os.path.join(self.storage_dir, "tls.pcap")

            # Craft polarproxy command.
            polarproxy_args = [
                self.polar_path,
                # Provide debugging output incase TLS MITMing fails for some reason.
                "-d",
                # PCAP to write to.
                "-w",
                self.pcap,
                # Write data to PCAP once a second so it's always there when the proc gets killed.
                "--autoflush",
                "1",
                # Specify CA cert that client VM will be expecting.
                "--cacert",
                f"load:{self.cert}:{self.password}",
                # Always sign generated certs with PP's root CA, even when original server cert isn't trusted.
                "--leafcert",
                "sign",
                "--ruleset",
                self.ruleset,
                # Allow clients to not provide an SNI
                "--nosni",
                "nosni.example.org",
                # LISTEN-IP             IPv4 or IPv6 address to bind proxy to.
                # LISTEN-PORT           TCP port to bind proxy to.
                # DECRYPTED-PORT        TCP server port to use for decrypted traffic in PCAP.
                # EXTERNAL-PORT         TCP port for proxy to connect to. Default value is same as LISTEN-PORT.
            ]
            # One -p per intercepted port. Netresec documents -p as repeatable
            # and it is verified working on this build (2.0.1.0).
            for port, lp in sorted(self.listen_ports.items()):
                polarproxy_args += ["-p", f"{self.host_ip},{lp},80,{port}"]

            # Open up log file handle
            self.log_file = open(os.path.join(self.storage_dir, "polarproxy.log"), "w")

            # Log PolarProxy command for safe keeping
            self.log_file.write(f"{' '.join(polarproxy_args)}\n")
            self.log_file.flush()

            try:
                self.proc = subprocess.Popen(polarproxy_args, stdout=self.log_file, stderr=self.log_file, shell=False)
            except (OSError, subprocess.SubprocessError) as e:
                log.info(
                    "Failed to start PolarProxy (host=%s, port=%s, dump_path=%s, log=%s). Error(%s)",
                    self.host_ip,
                    self.listen_port,
                    self.pcap,
                    self.log_file,
                    str(e)
                )
                self.log_file.close()
                self.log_file = None
                return

            log.info(
                "Started PolarProxy with PID %d (host=%s, port=%s, dump_path=%s, log=%s)",
                self.proc.pid,
                self.host_ip,
                self.listen_port,
                self.pcap,
                self.log_file,
            )

    def stop(self):
        """Set stop PolarProxy capture."""
        self.do_run = False

        if self.log_file:
            self.log_file.close()
            self.log_file = None

        try:
            if self.proc and self.proc.poll() is None:
                log.info("Stopping PolarProxy")
                self.proc.terminate()
                self.proc.wait()

        except subprocess.SubprocessError as e:
            log.error("Failed to shutdown PolarProxy module: %s", e)
        finally:
            self.proc = None
            log.info("Cleaning up PolarProxy iptables rules")
            for port, lp in getattr(self, "enabled_ports", []) or [(self.tlsport, self.listen_port)]:
                try:
                    rooter("polarproxy_disable", self.host_iface, self.machine.ip, str(port), str(lp))
                except Exception:
                    log.exception("Failed to remove firewall rule for port %s", port)
