# opsdroid-skill-networkinfo
Network object information skills for Opsdroid.

A skill for [opsdroid](https://github.com/opsdroid/opsdroid) designed to
support numerous network object lookup tasks.

## Requirements

- <https://pypi.org/project/aslookup/>

## Configuration

- `resolvers`: Optional. IP address(es) of one or more resolvers to use for
  resolving DNS queries.
    - Default: the local stub resolver configuration will be used.
- `service`: Optional. Service to utilize for querying ASN information for IP
  addresses.
    - Supported values: either `cymru` or `shadowserver`.
    - Default: `cymru`
    - Default: if omitted, the local stub resolver configuration will be used.

## Usage

```
skills:
  networkinfo: {}
```

