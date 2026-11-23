"""Is the affected product a mainstream cloud component? (Neo 2026-11-21: the team channel gets P0s about what FSI /
web3 customers run on AWS — nginx, Java, PHP, Linux, MySQL …; a language's own flaw (Java, Rust, Go …); web3
nodes and toolchains (geth, Solana, OpenZeppelin …) — not WhatsApp, Windows desktop, SAP, network appliances,
industrial control or niche self-hosted web apps.)

Since 2026-11-22 this is the P0 wall's taxonomy (radar.p0class): cloud ⇔ the product's group is a cloud group. One list,
so the wall and the team channel can never disagree. Decided from the event's public title and entities
(publish._summary → `cloud_stack`); subscriptions filter on it (notify FILTER_FIELDS["cloud_stack"]). The site keeps
every P0. Replay 2026-11-22: 51 vulnerability P0s since 09-01, 14 cloud — exactly the set the former regex list gave."""
from __future__ import annotations

from radar import p0class


def is_cloud_stack(title: str, entities: list[str] | None = None) -> bool:
    """The event's affected product (the product its title names first) is in a cloud group."""
    return p0class.place(title, entities).cloud
