# opsdroid-skill-networkinfo
Network object information skills for Opsdroid.

A skill for [opsdroid](https://github.com/opsdroid/opsdroid) designed to
support numerous network object lookup tasks.

## Requirements

- <https://pypi.org/project/aslookup/>

## Configuration

- `ipapi_key`: Optional. API key for <https://ipapi.co/> service.
    - Default: no key, which defaults to a free account with a limited query
      allowance.
- `resolvers`: Optional. List of one or more IP addresses of resolvers to use
  for resolving DNS queries.
    - Default: the local stub resolver configuration will be used.
- `service`: Optional. Service to utilize for querying ASN information for IP
  addresses.
    - Supported values: either `cymru` or `shadowserver`.
    - Default: `cymru`

## Usage

```
skills:
  networkinfo: {}
```

