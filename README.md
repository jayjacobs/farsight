farsight
========

This package wraps the API for Farsight's DNSDN API documented at <https://api.dnsdb.info/>.

It requires that you have a valid API key prior to running this code. The API key can be stored in an .ini file, passed in programatically or entered interactively (if running in an R console). Once you have a valid API key, you can run of the two types of queries offered by the API, the `rrset` or `rdata` query.

Can be installed with `devtools`:

``` {.r}
devtools::install_github("jayjacobs/farsight")
```

Some example commands:

``` {.r}
# pull names that resolved to an IP
iphistory <- rdata("113.10.174.118")

# get everything for a simple domain
bp <- rrset("beechplane.com")

# just get the SOA record for it
bp.soa <- rrset("beechplane.com", rrtype="SOA")

# get just the name servers from the top level com domain
bp.ns <- rrset("beechplane.com", rrtype="NS", bailiwick="com.")

# look at 10 most recent rrnames at a given name server
ns10 <- rdata("ns5.value-domain.com", type="name", limit=10)
```
