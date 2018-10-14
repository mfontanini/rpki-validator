RPKI validator
===

This is an RPKI validator written in Rust that provides a subset of the features provided
by [RIPE's RPKI validator](https://github.com/RIPE-NCC/rpki-validator). These include:

* Downloading RPKI repositories via rsync and validating the records in them.
* Providing an API to query for the validity of an advertisement. The API provided uses
the same paths and formats as RIPE's validator, allowing swapping them transparently.

This application wouldn't exist if it wasn't for [NLnet Labs](https://github.com/NLnetLabs)
amazing [library](https://github.com/NLnetLabs/rpki-rs) that really does all the heavy work.
The code in the `processor` module is based on their
[routinator](https://github.com/NLnetLabs/routinator) project. Thanks to them for putting
all that hard work into those projects!

# Why?

This implementation, while lacking many features, has a few advantages over RIPE's validator.
Among them:

* The memory footprint is much smaller. Using all 5 RIR repositories via rsync on RIPE's validator,
memory usage can go up to several GBs. This implementation instead uses something around
30MB of RAM.
* Record validation is considerably faster. A lot of this processing speed comes simply from using
[rpki-rs](https://github.com/NLnetLabs/rpki-rs) but I imagine this is also due to the fact that
everything is kept in memory rather than in a database on the filesystem. As an example, in my
laptop it takes about 2 seconds to validate the entire _LACNIC_ repository, whereas it takes about
100 to do the same when running RIPE's one.
* Any subsequent rsync call after the initial one per trust anchor, only new/modified
files are processed. This means that if nothing in the repository has changed, the validator
won't re-validate everything because there's really nothing to be validated. Records are mapped
to the particular file they came from so whenever it's either modified or deleted, the associated
records get invalidated. This reduces the CPU usage and only uses it when there's actually
something to validate.
* Consistently fast API. While doing some tests, I noticed RIPE's validator's average response 
time for validation API calls would be around 150ms per call, having sporadic spikes which could
go up to 20 seconds. This validator replies consistently at around 15ms. Validating an
advertisement is O(1) and finding matched/unmatched records takes about 1.5 microseconds in 
a 2.2ghz CPU.
* [Prometheus](https://prometheus.io/) metrics are exposed via an HTTP endpoint so it's possible
to set up alerts or dashboards and make sure the application is working fine.

Personally, I wanted to write something using Rust as my first project using the language and
this seemed like a great excuse.

# API

The exposed _JSON_ API has only one endpoint to query for the validity of an advertisement:

```
http://endpoint/api/v1/validity/AS<number>/<prefix>
```

For example, using `curl` and `jq` to pretty-print the JSON output:

```bash
$ curl http://127.0.0.1:8080/api/v1/validity/AS13335/1.1.1.0/24 2>/dev/null | jq
{
  "validated_route": {
    "route": {
      "origin_asn": "AS13335",
      "prefix": "1.1.1.0/24"
    },
    "validity": {
      "VRPs": {
        "matched": [
          {
            "asn": "AS13335",
            "max_length": 24,
            "prefix": "1.1.1.0/24"
          }
        ],
        "unmatched_as": [],
        "unmatched_length": []
      },
      "description": "VRPs cover prefix",
      "reason": "",
      "state": "Valid"
    }
  }
}
```

# Metrics

A [prometheus](https://prometheus.io/) endpoint is exposed at `/mgmt/metrics` so you can
set up alerts, dashboards to make sure everything's running smoothly.

# Docker image

The provided `Dockerfile` will build a _docker_ image using any `tal` files inside the _tal_
directory.

# ARIN tal

The _ARIN_ TAL file is not provided by default because they have a pretty strict policy on the
user of it. You can go ahead and download it from [this link](https://www.arin.net/resources/rpki/tal.html)
and place it in the `tal` directory. Make sure to download the version using the *RFC 7730* format.
