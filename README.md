# adguardhome-pauser
A daemon that pauses protection if specified websites are accessed 

# What is the point
Some media websites might refuse to load if adverising-related domains fail to resolve. 
This project aims to temporarily disable the AdGuardHome protection for the client/network when a specified domains that have these anti-adblock measures are queried.  

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

# Limitations
If the client/server has high TTL, or there is some kind of local DNS caching on the client-side, the request may not go through AdGuardHome at all, and the daemon can't see, and do anything
