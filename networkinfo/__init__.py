import logging

from aslookup import get_as_data
from defang import refang
from dns.resolver import NXDOMAIN, Resolver
from opsdroid.matchers import match_regex
from opsdroid.skill import Skill
from voluptuous import Optional

CONFIG_SCHEMA = {
    Optional("resolver"): list,
    Optional("service"): str,
}

DEFAULT_ASN_SERVICE = "cymru"

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

    @match_regex(
        r"asn (?P<ip>(\d{1,3}\.){3}\d{1,3})", matching_condition="fullmatch"
    )
    async def asn_lookup(self, message):
        """asn - return ASN information for requested IP address"""

        ip = message.entities["ip"]["value"].strip()
        as_info = get_as_data(
            ip,
            service=self.config.get("service", DEFAULT_ASN_SERVICE),
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
        """dns - return DNS A record resolution for requested IP address"""

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
