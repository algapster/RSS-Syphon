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
        {"name": "zdi-upcoming", "url": "https://www.zerodayinitiative.com/rss/upcoming/"},
        {"name": "zdi-analyzed", "url": "https://www.zerodayinitiative.com/rss/published/"},
        {"name": "seclists-bugtraq", "url": "https://seclists.org/rss/bugtraq.rss"},
        {"name": "seclists-full", "url": "https://seclists.org/rss/fulldisclosure.rss"},
        {"name": "seclists-oss", "url": "https://seclists.org/rss/oss-sec.rss"},
        {"name": "inthewild", "url": "https://raw.githubusercontent.com/gmatuz/inthewilddb/master/rss.xml"},
        {"name": "center-for-internet-security", "url": "https://www.cisecurity.org/feed/advisories"}
    ]
}

keywords = {
    "last_modified": "2024-02-29",
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
        "ibm",
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
