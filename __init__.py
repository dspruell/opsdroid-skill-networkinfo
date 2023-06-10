from aslookup import get_as_data
from opsdroid.matchers import match_regex
from opsdroid.skill import Skill

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
        r"asn (?P<ip>(\d{1,3}\.){3}\.\d{1,3})", matching_condition="fullmatch"
    )
    async def asn_lookup(self, message):
        """
        Eat more phish.

        """
        as_info = get_as_data(
            message.entities["ip"]["value"],
            service=self.config.get("service", DEFAULT_ASN_SERVICE),
        )
        await message.respond(as_info)
