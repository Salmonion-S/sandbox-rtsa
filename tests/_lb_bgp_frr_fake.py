import json
from typing import Any, Dict, List, Optional, Sequence

from core.lb_bgp_speaker import BgpCommandRunner, CmdResult


class FakeFrr(BgpCommandRunner):
    def __init__(self, asn: Optional[int] = 65001, peers: Optional[Dict[str, str]] = None) -> None:
        self.asn = asn
        self.peers = dict(peers if peers is not None else {"10.0.0.1": "Established"})
        self.unexpected: Dict[str, str] = {}
        self.originated: List[str] = []
        self.calls: List[List[str]] = []
        self.daemon_up = True
        self.timeout = False
        self.oversize = False
        self.garbage = False
        self.running_config = "router bgp 65001\n neighbor 10.0.0.1 password SuperSecret123\n neighbor 10.0.0.1 remote-as 65000\n"
        self.ip_routes: List[Dict[str, Any]] = []

    async def run(self, argv: Sequence[str], timeout: float, limit: int) -> CmdResult:
        self.calls.append(list(argv))
        if self.timeout:
            return CmdResult(None, timed_out=True)
        binary = argv[0]
        if binary.endswith("/ip") or binary == "ip":
            return CmdResult(0, json.dumps(self.ip_routes))
        commands = [argv[i + 1] for i, a in enumerate(argv) if a == "-c"]
        if not self.daemon_up:
            return CmdResult(1, "", "Exiting: failed to connect to any daemons.")
        if self.garbage:
            return CmdResult(0, "this is not json")
        if self.oversize:
            return CmdResult(0, "{" + "x" * 10, truncated=True)
        if commands and commands[0] == "configure terminal":
            return self._configure(commands)
        text = " ".join(commands)
        if text == "show version":
            return CmdResult(0, "FRRouting 8.4.4 (fake) on Linux\nCopyright\n")
        if text == "show running-config":
            return CmdResult(0, self.running_config)
        if text.endswith("unicast summary json"):
            if self.asn is None:
                return CmdResult(0, "{}")
            peers = {a: self._peer(s) for a, s in {**self.peers, **self.unexpected}.items()}
            return CmdResult(0, json.dumps({"routerId": "1.1.1.1", "as": self.asn, "peers": peers}))
        if " unicast " in text and text.endswith(" json"):
            prefix = text.split(" unicast ")[1].replace(" json", "")
            if prefix in self.originated:
                advertised = {a: {} for a, s in self.peers.items() if s == "Established"}
                return CmdResult(0, json.dumps({
                    "prefix": prefix, "advertisedTo": advertised,
                    "paths": [{"sourced": True, "local": True, "valid": True}],
                }))
            return CmdResult(0, "{}")
        return CmdResult(1, "% Unknown command")

    @staticmethod
    def _peer(state: str) -> Dict[str, Any]:
        return {"state": state, "peerUptimeMsec": 5000, "pfxRcd": 0, "pfxSnt": 1}

    def _configure(self, commands: List[str]) -> CmdResult:
        router = next((c for c in commands if c.startswith("router bgp ")), "")
        asn = int(router.split()[-1]) if router else None
        if self.asn is None:
            self.asn = asn
        elif asn != self.asn:
            return CmdResult(1, f"BGP is already running; AS is {self.asn}")
        last = commands[-1]
        if last.startswith("no network "):
            prefix = last.split()[-1]
            if prefix not in self.originated:
                return CmdResult(1, "% Can't find static route specified")
            self.originated.remove(prefix)
        elif last.startswith("network "):
            prefix = last.split()[-1]
            if prefix not in self.originated:
                self.originated.append(prefix)
        else:
            return CmdResult(1, "% Unknown command")
        return CmdResult(0, "")
