from aslookup import get_as_data
from opsdroid.matchers import match_regex
from opsdroid.skill import Skill
from voluptuous import Optional

CONFIG_SCHEMA = {
    Optional("service"): str,
}

DEFAULT_ASN_SERVICE = "cymru"


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
        """
        Eat more phish.

        """
        ip = message.entities["ip"]["value"]
        as_info = get_as_data(
            ip,
            service=self.config.get("service", DEFAULT_ASN_SERVICE),
        )
        await message.respond(
            f"{ip} {as_info.handle} | {as_info.cc} | {as_info.name}"
        )
