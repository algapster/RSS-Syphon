"""
# Feed data
Includes feed list and keywords list
Keywords contain ignored keywords and static keywords that can be joined with additional lists from other sources
  search_keywords = keywords["static_keywords"]
  search_keywords.extend(additional_keywords)

-> Banned feeds
--> https://securelist.com/feed/ | site throws in random keywords
--> https://feeds.megaphone.fm/darknetdiaries | majorly irrelevant
--> https://www.blackhillsinfosec.com/feed | not relevant most times
--> https://thecyberwire.libsyn.com/rss | spammy
--> https://threatpost.com/ | Defunct No new vulns
Feeds and keywords should be reviewed periodically and updated as needed
"""

rss_feed_list = {
    "news": [
        {"name": "Bleepingcomputer", "url": "https://www.bleepingcomputer.com/feed/"},
        {"name": "Wired ", "url": "https://www.wired.com/feed/category/security/latest/rss"},
        {"name": "News ≈ Packet Storm", "url": "https://rss.packetstormsecurity.com/news/"},
        {"name": "zdnet.com", "url": "https://www.zdnet.com/topic/security/rss.xml"},
        {"name": "threatpost", "url": "https://threatpost.com/feed/"},
        {"name": "arxiv", "url": "https://export.arxiv.org/api/query?search_query=cat:cs.CR&sortBy=submittedDate&sortOrder=descending&max_results=50"},
        {"name": "packetstormsecurity", "url": "https://rss.packetstormsecurity.com/files/"},
        {"name": "portswigger", "url": "https://portswigger.net/daily-swig/rss"},
        {"name": "rapid7", "url": "https://blog.rapid7.com/rss/"},
        {"name": "checkpoint", "url": "https://research.checkpoint.com/feed/"},
        {"name": "isc.sans.edu", "url": "https://isc.sans.edu/rssfeed_full.xml"},
        {"name": "msrc.microsoft", "url": "https://msrc.microsoft.com/blog/feed"}
    ],
    "cve": [
        {"name": "esecurityplanet", "url": "https://www.esecurityplanet.com/feed/"},
        {"name": "secpod", "url": "https://www.secpod.com/blog/feed/"},
        {"name": "tacsecurity", "url": "https://tacsecurity.com/feed/"},
        {"name": "Medium ", "url": "https://medium.com/feed/realmodelabs"},
        {"name": "seclists-full", "url": "https://seclists.org/rss/fulldisclosure.rss"},
        {"name": "seclists-oss", "url": "https://seclists.org/rss/oss-sec.rss"},
        {"name": "inthewild", "url": "https://raw.githubusercontent.com/gmatuz/inthewilddb/master/rss.xml"},
        {"name": "center-for-internet-security", "url": "https://www.cisecurity.org/feed/advisories"},
        {"name": "SANS Internet Storm Center (ISC)", "url": " https://isc.sans.edu/rssfeed.xml"},
        {"name": "CERT Coordination Center (CERT/CC) Vulnerability Notes", "url": " https://www.kb.cert.org/vulfeed"},
        {"name": "nedwill’s security blog", "url": "https://nedwill.github.io/blog/feed.xml"},
        {"name": "Hanno's blog -", "url": "https://blog.hboeck.de/feeds/index.rss2"},
        {"name": "Active Directory Security", "url": "https://adsecurity.org/?feed=rss2"},
        {"name": "DigiNinja", "url": "https://digi.ninja/rss.xml"},
        {"name": "enigma0x3", "url": "https://enigma0x3.net/feed/"},
        {"name": "ZeroSec - Adventures In Information Security", "url": "https://blog.zsec.uk/rss/"},
        {"name": "Max Justicz", "url": "https://justi.cz/feed.xml"},
        {"name": "Blog of Osanda", "url": "https://osandamalith.com/feed/"},
        {"name": "The Exploit Laboratory", "url": "https://blog.exploitlab.net/feeds/posts/default"},
        {"name": "The Human Machine Interface", "url": "https://h0mbre.github.io/feed.xml"},
        {"name": "Trail of Bits Blog", "url": "https://blog.trailofbits.com/feed/"},
        {"name": "Exodus Intelligence", "url": "https://blog.exodusintel.com/feed/"},
        {"name": "Diary of a reverse-engineer", "url": "https://doar-e.github.io/feeds/rss.xml"},
        {"name": "Sean Heelan's Blog", "url": "https://sean.heelan.io/feed/"},
        {"name": "MKSBen", "url": "https://mksben.l0.cm/feeds/posts/default?alt=rss"},
        {"name": "Mozilla Attack & Defense", "url": "https://blog.mozilla.org/attack-and-defense/feed/"},
        {"name": "Doyensec's Blog", "url": "https://blog.doyensec.com/atom.xml"},
        {"name": "Revers.engineering", "url": "https://revers.engineering/feed/"},
        {"name": "phoenhex team", "url": "https://phoenhex.re/feed.xml"},
        {"name": "Rhino Security Labs", "url": "https://rhinosecuritylabs.com/feed/"},
        {"name": "Zero Day Initiative - Blog", "url": "https://www.zerodayinitiative.com/blog?format=rss"},
        {"name": "BlackArrow", "url": "https://www.blackarrow.net/feed/"},
        {"name": "PortSwigger Research", "url": "https://portswigger.net/research/rss"},
        {"name": "research.securitum.com", "url": "https://research.securitum.com/feed/"},
        {"name": "Corelan Team", "url": "https://www.corelan.be/index.php/feed/"},
        {"name": "NCC Group Research", "url": "https://research.nccgroup.com/feed/"},
        {"name": "Alexander Popov", "url": "https://a13xp0p0v.github.io/feed.xml"},
        {"name": "Windows Internals Blog", "url": "https://windows-internals.com/feed/"}
        {"name": "Windows Internals Blog", "url": "https://windows-internals.com/feed/"},
        {"name": "nist-analyzed", "url": "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyzed.xml"},
        {"name": "nist-upcoming", "url": "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml"},
        {"name": "vulners", "url": "https://vulners.com/rss.xml"},
        {"name": "seclists-bugtraq", "url": "https://seclists.org/rss/bugtraq.rss"},
        {"name": "seclists-full", "url": "https://seclists.org/rss/fulldisclosure.rss"},
        {"name": "seclists-oss", "url": "https://seclists.org/rss/oss-sec.rss"},
        {"name": "inthewild", "url": "https://raw.githubusercontent.com/gmatuz/inthewilddb/master/rss.xml"},
        {"name": "center-for-internet-security", "url": "https://www.cisecurity.org/feed/advisories"}
    ]
}

keywords = {
    "last_modified": "2024-06-13",

    "ignored": [
        "hiring"
    ],
    "static_keywords": [
        "android",
        "apple",
        "arin",
        "aruba",
        "azure",
        "beyond trust",
        "bomgar",
        "centrify",
        "checkmk",
        "chrome",
        "cisco",
        "code42",
        "connectwise",
        "debian",
        "defender",
        "designcad",
        "digicert",
        "docusign",
        "duo",
        "fortinet",
        "fortiswitch",
        "google",
        "global protect",
        "hp",
        "hubspot",
        "idaptive",
        "infoblox",
        "ingram micro",
        "ipad",
        "iphone",
        "iris",
        "it glue",
        "ivanti",
        "jamf",
        "juniper ",
        "jwt",
        "knowbe4",
        "lenovo",
        "lucid",
        "macbook",
        "macos",
        "meraki",
        "microsoft",
        "mozilla firefox",
        "defender",
        "office",
        "nessus",
        "netapp",
        "notepad++",
        "office365",
        "okta",
        "palo alto",
        "parallels",
        "paycor",
        "pycharm",
        "rapidfire",
        "salesforce",
        "secret server",
        "slack",
        "sonicwall",
        "supermicro",
        "synnex",
        "webex",
        "wiline",
        "windows",
        "zoom"
    ]
}
