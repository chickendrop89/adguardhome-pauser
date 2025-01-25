# adguardhome-pauser
A daemon that pauses protection if specified websites are accessed.

# What is the point
Some media websites might refuse to load content if adverising-related domains fail to resolve.

This project aims to temporarily disable the AdGuardHome protection for the client/network,
when the user-specified domains that have these anti-adblock measures are queried.

The function of this project is best showcased on websites that don't show an anti-adblock popup right away, 
but after selecting some piece of content (ex: unnamed movie websites)

# Running the daemon:
Clone the repositroy, and then install requirements:
```shell
pip install -r requirements.txt
```

Open your editor of choice, and edit `config.py`:
```shell
nano config.py
```

AdGuard credentials need to be exported as environment variables.
You can either do this, or prefix the daemon script with them.
```shell
export ADGUARD_USERNAME=<your user>
export ADGUARD_PASSWORD=<your pass>
```

Run the daemon:
```shell
python ./daemon.py
```

#### Help, the daemon doesn't catch my queries!
- Try to tune the `QUERY`-related variables.
- It's best to start with increasing the `QUERY_LIMIT`, 
and reducing the `QUERY_INTERVAL` until you find the ideal values.

#### Format of the "pausers" file
- The parser expects every website to be on it's own line.
- Wildcards are not supported, refer to `PAUSERS_SUBDOMAINS` instead.
- Regex is not supported.

# Testing the daemon
Best way to test this daemon is using DNS lookup tools.
```shell
# Linux
dig @<AGH server ip> <your pauser domain>

# Windows
nslookup <your pauser domain> <AGH server ip>
```

Example:
```shell
# Linux
dig @localhost example.com

# Windows
nslookup example.com localhost
```

Then just observe if the daemon catched the query in the command line.

# Limitations
If the client/server has high TTL, or there is some kind of local DNS caching on the client-side, 
the request may not go through AdGuardHome at all, and the daemon can't see, and do anything.
