# adguardhome-pauser
A daemon that pauses protection if specified websites are accessed.

# What is the point
Some media websites may refuse to load content if advertising-related domains are blocked.

This project aims to temporarily disable AdGuardHome protection for the client/network
when the user-specified domains with anti-adblock measures are queried.

This functionality is most effective on websites that do not immediately display an anti-adblock popup
but do so after a user selects some content (e.g., unnamed movie websites 🏴‍☠️).

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
If the domain is accessed frequently and the client/server has an extremely high TTL, or if there is client-side caching, the query may not go through AdGuardHome at all, preventing the daemon from detecting and acting on it.
