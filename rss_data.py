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

  
    ],
    "cve": [
        {"name": "zdi-analyzed", "url": "https://www.zerodayinitiative.com/rss/published/"},
        {"name": "seclists-bugtraq", "url": "https://seclists.org/rss/bugtraq.rss"},
        {"name": "seclists-full", "url": "https://seclists.org/rss/fulldisclosure.rss"},
        {"name": "seclists-oss", "url": "https://seclists.org/rss/oss-sec.rss"},
        {"name": "inthewild", "url": "https://raw.githubusercontent.com/gmatuz/inthewilddb/master/rss.xml"},
        {"name": "center-for-internet-security", "url": "https://www.cisecurity.org/feed/advisories"},
        {"name": "SANS Internet Storm Center (ISC)", "url": " https://isc.sans.edu/rssfeed.xml"},
        {"name": "CERT Coordination Center (CERT/CC) Vulnerability Notes", "url": " https://www.kb.cert.org/vulfeed"},
        {"name": "nedwill’s security blog", "url": "https://nedwill.github.io/blog/feed.xml"},
        {"name": "Realmode Labs - Medium", "url": "https://medium.com/feed/realmodelabs"},
        {"name": "Hanno's blog -", "url": "https://blog.hboeck.de/feeds/index.rss2"},
        {"name": "Active Directory Security", "url": "https://adsecurity.org/?feed=rss2"},
        {"name": "Mogozobo", "url": "https://www.mogozobo.com/?feed=rss2"},
        {"name": "DigiNinja", "url": "https://digi.ninja/rss.xml"},
        {"name": "enigma0x3", "url": "https://enigma0x3.net/feed/"},
        {"name": "ZeroSec - Adventures In Information Security", "url": "https://blog.zsec.uk/rss/"},
        {"name": "Max Justicz", "url": "https://justi.cz/feed.xml"},
        {"name": "Blog of Osanda", "url": "https://osandamalith.com/feed/"},
        {"name": "The Exploit Laboratory", "url": "https://blog.exploitlab.net/feeds/posts/default"},
        {"name": "Linux Audit", "url": "https://linux-audit.com/feed/"},
        {"name": "markitzeroday.com", "url": "https://markitzeroday.com/feed.xml"},
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

    ]
}

keywords = {
    "last_modified": "2024-03-07",
    "ignored": [
        "hiring"
    ],
    "static_keywords": [
        "adobe",
        "airmagnet survey ",
        "amazon",
        "android",
        "apple",
        "arin",
        "aruba",
        "autoptimize",
        "aws",
        "azure",
        "beyond trust",
        "bomgar",
        "centos",
        "centrify",
        "checkmk",
        "chrome",
        "cisco",
        "code42",
        "connectwise",
        "crash plan",
        "debian",
        "defender",
        "dell",
        "designcad",
        "digicert",
        "docusign",
        "duo",
        "fortianalyzer",
        "forticloud",
        "fortigate",
        "fortimanager",
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
        "linux",
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
        "pluralsight",
        "pulse secure",
        "putty",
        "pycharm",
        "rapidfire",
        "ricoh",
        "rubrick",
        "salesforce",
        "secret server",
        "sentinel",
        "slack",
        "sonicwall",
        "supermicro",
        "synnex",
        "ubuntu",
        "vcenter",
        "veeam",
        "vmware",
        "vsphere",
        "webex",
        "wiline",
        "windows",
        "winscp",
        "workspace",
        "yubikey",
        "zoom",
        "zscaler",
        "openai",
        "wmvare"


    ]
}
