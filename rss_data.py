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
        {"name": "nist-analyzed", "url": "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyzed.xml"},
        {"name": "nist-upcoming", "url": "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml"},
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
               "assets",
        "aws",
        "confluence",
        "adobe",
        "airmagnet",
        "netally",
        "alienvault",
        "amazon",
        "android",
        "apple",
        "arin",
        "atlassian",
        "autoptimize",
        "azure",
        "beyondtrust",
        "bomgar",
        "bomgar",
        "cdw",
        "centos",
        "centrify",
        "checkmk",
        "chrome",
        "cisco",
        "cisco",
        "connectwise",
        "crash plan",
        "debian",
        "decisions",
        "defnder",
        "dell",
        "digicert",
        "docusign",
        "duo",
        "fortianalyzer",
        "forticloud",
        "fortigate",
        "fortimanager",
        "fortinet",
        "fortiswitch",
        "gcp",
        "globalprotect",
        "google cloud",
        "google workspace",
        "horizon",
        "hp",
        "hubspot",
        "ibm",
        "idaptive",
        "imc",
        "infoblox",
        "ingram", 
        "ipad",
        "iphone",
        "it glue",
        "ivanti",
        "jamf"
        "jamfpro",
        "jwt",
        "knowbe4",
        "lenovo",
        "linux",
        "linux",
        "lucid",
        "macbook",
        "macos",
        "meraki",
        "microsoft",
        "nessus",
        "netapp",
        "office365",
        "okta",
        "overland",
        "parallels",
        "paycor",
        "pluralsight",
        "pulse secure",
        "rapidfire",
        "ricoh",
        "rubrick",
        "salesforce",
        "secret server",
        "slack",
        "supermicro",
        "synnex",
        "tenable", 
        "nessus", 
        "ubuntu",
        "vcenter",
        "veeam",
        "vmware",
        "vsphere",
        "wiline",
        "windows",
        "windows 10",
        "windows 11",
        "zoom"
    ]
}
