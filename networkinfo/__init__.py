import logging
import ssl
from io import StringIO
from subprocess import run

import ipapi
from aslookup import get_as_data
from defang import refang
from dns.resolver import NXDOMAIN, Resolver
from opsdroid.matchers import match_regex
from opsdroid.skill import Skill
from tabulate import tabulate
from tls_probe import get_sock_info
from voluptuous import Optional

CONFIG_SCHEMA = {
    Optional("resolver"): list,
    Optional("service"): str,
}

DEFAULT_ASN_SERVICE = "cymru"
DEFAULT_CONNECTION_TIMEOUT = 5
DEFAULT_IPAPI_KEY = None
DEFAULT_IPCALC_CMD = "ipcalc-ng"

logger = logging.getLogger(__name__)


def _monowrap(s):
    """Wrap input string in monospace text markup."""

    return f"```{s}```"


class NetworkinfoSkill(Skill):
    # Needs support developed.
    #
    # @match_regex(
    #     r"asn-info (?P<ashandle>AS\d+)", matching_condition="fullmatch"
    # )
    # async def asn_info(self, message):
    #     asn_info = get_as_info(
    #         message.entities['ashandle']['value'],
    #         service="cymru"
    #     )
    #     await message.respond(as_info)

    async def _lookup_ip_ipapi(self, ip=None, output="json"):
        """Look up IP address information using ipapi API

        If the IP address is None, pass no address to the API and receive a
        lookup of the requesting client's IP address.

        """
        ipapi_key = self.config.get("ipapi_key", DEFAULT_IPAPI_KEY)
        ipinfo = ipapi.location(
            ip=ip,
            key=ipapi_key,
            output="json",
        )
        return ipinfo

    @match_regex(
        r"asn (?P<ip>(\d{1,3}\.){3}\d{1,3})", matching_condition="fullmatch"
    )
    async def asn_lookup(self, message):
        """asn - Return ASN information for a requested IP address"""

        ip = message.entities["ip"]["value"].strip()
        asn_service = self.config.get("service", DEFAULT_ASN_SERVICE)
        as_info = get_as_data(
            ip,
            service=asn_service,
        )
        await message.respond(
            _monowrap(
                f"{ip:15} {as_info.handle} | {as_info.cc} | {as_info.as_name}"
            )
        )

    # @match_regex(
    #     r"dns ((?P<ip>(\d{1,3}\.){3}\d{1,3})|(?P<fqdn>(.*)))",
    #     matching_condition="fullmatch",
    # )
    @match_regex(
        r"dns\s+(?P<ip>(\d{1,3}\.){3}\d{1,3})\s*",
        matching_condition="fullmatch",
    )
    @match_regex(
        r"dns\s+(?P<fqdn>(\S+))\s*",
        matching_condition="fullmatch",
    )
    async def dns_lookup(self, message):
        """dns - Return DNS resolution for a requested name or IP address"""

        if message.entities.get("ip"):
            ip = message.entities["ip"]["value"].strip()
            fqdn = None
        elif message.entities.get("fqdn"):
            fqdn = message.entities["fqdn"]["value"].strip().lower()
            ip = None

        logger.debug("Received message: %s", message)
        logger.debug("Extracted matches: ip=%s, fqdn=%s", ip, fqdn)

        resolver = Resolver()
        _config_resolvers = self.config.get("resolvers")
        if _config_resolvers:
            logger.debug(
                "Using specified DNS resolvers: %s", _config_resolvers
            )
            resolver.nameservers = _config_resolvers

        try:
            if fqdn:
                fqdn = refang(fqdn)
                logger.debug("Final parsed FQDN: %s", fqdn)
                answer = resolver.resolve(fqdn)
            elif ip:
                answer = resolver.resolve_address(ip)
            answer = [str(addr) for addr in answer]
        except NXDOMAIN:
            answer = ["NXDOMAIN"]
        finally:
            answer = ", ".join(answer)

        qterm = ip or fqdn
        await message.respond(_monowrap(f"{qterm}: {answer}"))

    @match_regex(
        r"ip\s+(?P<ip>(\S+))\s*",
        matching_condition="fullmatch",
    )
    async def ip_lookup(self, message):
        """ip - Return geoIP information about a requested IP address"""

        ip = message.entities["ip"]["value"].strip()

        logger.debug("Received message: %s", message)
        logger.debug("Extracted matches: ip=%s", ip)

        ipinfo = self._lookup_ip_ipapi(ip=ip)

        resp = (
            f'Location: [{ipinfo["country_code"]} {ipinfo["country"]} / '
            f'{ipinfo["region"]} / {ipinfo["city"]}\n'
            f'ASN:      {ipinfo["asn"]} / {ipinfo["org"]}'
        )

        await message.respond(_monowrap(f"{resp}"))

    @match_regex(
        r"ipcalc\s+(?P<ip>((?:\S+|\S+-\S+)))\s*",
        matching_condition="fullmatch",
    )
    async def ipcalc_query(self, message):
        """ipcalc - Return IP address subnet calculation for specified CIDR"""

        ip = message.entities["ip"]["value"].strip()
        ipcalc_cmd = self.config.get("ipcalc_cmd", DEFAULT_IPCALC_CMD)

        logger.debug("Received message: %s", message)
        logger.debug("Extracted matches: ip=%s", ip)

        try:
            cmdargs = [ipcalc_cmd, ip]
            # Handle address range deaggregation
            if "-" in ip and "ipcalc-ng" in ipcalc_cmd:
                cmdargs.insert(1, "-d")
            output = run(cmdargs, capture_output=True, text=True)
            output = output.stdout.expandtabs()
        except FileNotFoundError as e:
            output = f"error executing command: {e}"

        await message.respond(_monowrap(f"{output}"))

    @match_regex(
        r"portcheck\s+(?P<ip>\S+)\s+(?P<port>\d+)\s*",
        matching_condition="fullmatch",
    )
    async def check_port_connect(self, message):
        """portcheck - Return result of connection test to an IP and port"""

        ip = message.entities["ip"]["value"].strip()
        port = message.entities["port"]["value"].strip()
        timeout = str(
            self.config.get("connection_timeout", DEFAULT_CONNECTION_TIMEOUT)
        )

        logger.debug("Received message: %s", message)
        logger.debug("Extracted matches: ip=%s, port=%s", ip, port)
        logger.debug("Settings: timeout=%s", timeout)

        try:
            cmdargs = [
                "torsocks",
                "nc",
                "-n",
                "-v",
                "-z",
                "-w",
                timeout,
                ip,
                port,
            ]
            logger.debug(
                "About to call subprocess.run with cmdargs: %s", cmdargs
            )
            output = run(cmdargs, capture_output=True, text=True)
            logger.debug("Command for torsocks returned output: %s", output)
            # Failed connection results in output to stderr, so capture either.
            output = output.stdout or output.stderr
        except FileNotFoundError as e:
            output = f"error executing command: {e}"

        await message.respond(_monowrap(f"{output}"))

    @match_regex(
        r"tls\s+(?P<host>\S+)\s+(?P<port>\d+)\s*",
        matching_condition="fullmatch",
    )
    async def tls_probe(self, message):
        """tls - Return information about a remote TLS service."""

        host = message.entities["host"]["value"].strip()
        port = message.entities["port"]["value"].strip()

        logger.debug("Received message: %s", message)
        logger.debug("Extracted matches: host=%s, port=%s", host, port)

        try:
            # Default to not validating TLS socket; the objective is to probe
            # it and get information, not to establish a connection securely,
            # and the risk of MitM is not a concern.
            conn_info = get_sock_info((host, port), validate=False)
        except (ConnectionRefusedError, ssl.SSLError) as e:
            err = f"Unable to establish SSL/TLS session: {e}"
            logger.error(err)
            await message.respond(_monowrap(f"{err}"))

        buf = StringIO()
        fp = conn_info["cert"].pop("fingerprints")
        exts = conn_info["cert"].pop("extensions")
        print("Connection:", file=buf)
        print(tabulate(conn_info["conn"].items(), tablefmt="plain"), file=buf)
        print("\nCertificate:", file=buf)
        print(tabulate(conn_info["cert"].items(), tablefmt="plain"), file=buf)
        print("\nFingerprints:", file=buf)
        print(tabulate(fp.items(), tablefmt="plain"), file=buf)
        print("\nExtensions:", file=buf)
        print(tabulate(exts.items(), tablefmt="plain"), file=buf)

        output = buf.getvalue()
        buf.close()

        await message.respond(_monowrap(f"{output}"))

    @match_regex(
        r"sourceip",
        matching_condition="fullmatch",
    )
    async def check_source_ip(self, message):
        """sourceip - Return the source IP address for an outbound request."""

        logger.debug("Received message: %s", message)

        # No arguments to receive information for our own IP address
        ipinfo = self._lookup_ip_ipapi()

        resp = (
            f'Location: [{ipinfo["country_code"]} {ipinfo["country"]} / '
            f'{ipinfo["region"]} / {ipinfo["city"]}\n'
            f'ASN:      {ipinfo["asn"]} / {ipinfo["org"]}'
        )

        await message.respond(_monowrap(f"{resp}"))
