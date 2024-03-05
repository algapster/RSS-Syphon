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
        {"name": "vulners", "url": "https://vulners.com/rss.xml"},
        {"name": "seclists-bugtraq", "url": "https://seclists.org/rss/bugtraq.rss"},
        {"name": "seclists-full", "url": "https://seclists.org/rss/fulldisclosure.rss"},
        {"name": "seclists-oss", "url": "https://seclists.org/rss/oss-sec.rss"},
        {"name": "inthewild", "url": "https://raw.githubusercontent.com/gmatuz/inthewilddb/master/rss.xml"},
        {"name": "tenable", "url": "https://www.tenable.com/cve/feeds?sort=newest"},
        {"name": "tenable-updated", "url": "https://www.tenable.com/cve/feeds?sort=updated"},
        {"name": "center-for-internet-security", "url": "https://www.cisecurity.org/feed/advisories"}
    ]
}

keywords = {
    "last_modified": "2024-02-29",
    "ignored": [
        "hiring"
    ],
    "static_keywords": [
        "Adobe",
        "AirMagnet Survey ",
        "alienvault",
        "Amazon Workpsace",
        "Amazon",
        "android",
        "Apple",
        "ARIN",
        "Aruba",
        "Autoptimize",
        "aws",
        "Azure",
        "Beyond Trust",
        "Bomgar",
        "CentOS",
        "Centrify",
        "CheckMK",
        "chrome",
        "Cisco",
        "Code42",
        "ConnectWise",
        "Crash Plan",
        "Debian",
        "Decisions",
        "Defender",
        "Dell",
        "DesignCAD",
        "DigiCert",
        "DocuSign",
        "duo",
        "FortiAnalyzer",
        "FortiCloud",
        "FortiGate",
        "FortiManager",
        "Fortinet",
        "FortiSwitch",
        "gcp",
        "Global Protect",
        "globalprotect",
        "google ",
        "Horizon",
        "HP",
        "HubSpot",
        "IBM",
        "idaptive",
        "Infoblox",
        "Ingram Micro",
        "IPad",
        "iphone",
        "IRIS",
        "IT Glue",
        "Ivanti",
        "Jamf",
        "Juniper ",
        "JWT",
        "KnowBe4",
        "Lenovo",
        "Linux",
        "Lucid",
        "MacBook",
        "macos",
        "meraki",
        "Microsoft",
        "Mozilla Firefox",
        "MS Defender",
        "MS Office",
        "Nessus",
        "NetApp",
        "Notepad++",
        "office365",
        "Okta",
        "Overland",
        "Palo Alto",
        "Parallels",
        "paycor",
        "PluralSight",
        "Pulse Secure",
        "Putty",
        "PyCharm",
        "RapidFire",
        "Ricoh",
        "Rubrick",
        "SalesForce",
        "Secret Server",
        "Sentinel",
        "Slack",
        "SonicWall",
        "SuperMicro",
        "Synnex",
        "Tenable",
        "Ubuntu",
        "vCenter",
        "Veeam",
        "Vmware",
        "vSphere",
        "Webex",
        "WiLine",
        "Windows",
        "WinSCP",
        "WorkSpace",
        "Yyubikey",
        "Zoom",
        "ZScaler"

    ]
}
