async def set_txt_record(name: str, value: str, ttl: int) -> None:
    """Set a DNS TXT record for ACME dns-01 validation.

    This is a replaceable hook: overwrite app/acme/challenge/dns_provider.py
    with logic that sets the TXT record in your DNS backend.
    """
    raise NotImplementedError('app/acme/challenge/dns_provider.py is not implemented. Replace it with a provider that sets/removes TXT records for ACME dns-01.')


async def remove_txt_record(name: str, value: str) -> None:
    """Remove a DNS TXT record that was used for ACME dns-01 validation.

    This is a replaceable hook: overwrite app/acme/challenge/dns_provider.py
    with logic that removes the TXT record in your DNS backend.
    """
    raise NotImplementedError('app/acme/challenge/dns_provider.py is not implemented. Replace it with a provider that sets/removes TXT records for ACME dns-01.')
