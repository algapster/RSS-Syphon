import logging
import re
import time
from bs4 import BeautifulSoup
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError, SlackApiRateLimitError

logger = logging.getLogger(__name__)

def init_slack_client(slack_token):
    return WebClient(token=slack_token)

def read_channel(client, channel_id, rss_type, pages_to_read):
    re_dict = {"links": [], "md5s": [], "fixed_cves": [], "seen_cves": []}
    
    try:
        conversation_history = []
        pages_to_read = int(pages_to_read)
        result = client.conversations_history(channel=channel_id)
        conversation_history.extend(result["messages"])

        while result["response_metadata"]["next_cursor"] is not None and pages_to_read > 0:
          result = client.conversations_history(channel=channel_id, cursor=result["response_metadata"]["next_cursor"])
          conversation_history.extend(result["messages"])
          pages_to_read = pages_to_read - 1

        # Process extracted messages to find links and MD5 hashes
        re_link = []
        link_regex = re.compile(r"(?:link\:.+?)(https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&\/=]*))", re.IGNORECASE)
        re_results = link_regex.findall(str(conversation_history))
        for re_result in re_results:
            if re_result not in re_link:
                re_link.append(re_result)
        
        re_md5 = []
        md5_regex = re.compile(r"(?:md5:\s)([a-f0-9]{32})", re.IGNORECASE)
        re_results = md5_regex.findall(str(conversation_history))
        for re_result in re_results:
            if re_result not in re_md5:
                re_md5.append(re_result)
        
        already_fixed_list = []
        already_seen_list = []
        
        if rss_type.lower() == "cve":
            cve_regex = re.compile(r"(CVE-20[0-9]{2}-\d+)", re.IGNORECASE)
            
            for dialog in conversation_history:
                if "reactions" in dialog:
                    if any(item['name'] == 'white_check_mark' for item in dialog.get("reactions", [])):
                        cve_dialog_results = cve_regex.findall(str(dialog))
                        for dialog_result in cve_dialog_results:
                            if dialog_result not in already_fixed_list:
                                already_fixed_list.append(dialog_result)
            
            cve_convo_results = cve_regex.findall(str(conversation_history))
            for convo_result in cve_convo_results:
                if convo_result not in already_seen_list:
                    already_seen_list.append(convo_result)
        
        re_dict = {"links": re_link, "md5s": re_md5, "fixed_cves": already_fixed_list, "seen_cves": already_seen_list}
    
    except SlackApiRateLimitError as e:
        delay = int(e.response.headers.get("Retry-After", 1))
        logger.warning(f"Rate limited. Retrying in {delay} seconds.")
        time.sleep(delay)
        return read_channel(client, channel_id, rss_type, pages_to_read)
    except SlackApiError as e:
        msg = f"Error fetching conversation data: {e.response.get('error', 'Unknown error')}"
        logger.error(msg)
    
    return re_dict

def post_message(client, channel_id, messages):
    for message in messages.split('\n---EOM---'):
        if message:
            try:
                result = client.chat_postMessage(
                    channel=channel_id,
                    text=message,
                    unfurl_links=False,
                    unfurl_media=False,
                    parse="mrkdwn"
                )
                logger.info(result)
            except SlackApiRateLimitError as e:
                delay = int(e.response.headers.get("Retry-After", 1))
                logger.warning(f"Rate limited. Retrying in {delay} seconds.")
                time.sleep(delay)
                post_message(client, channel_id, message)
            except SlackApiError as e:
                msg = f"Error posting message: {e}"
                logger.error(msg)

def clean_html(input_text):
    text = BeautifulSoup(input_text, "lxml").get_text(separator="\n")
    return re.sub('\n\n', '\n', text)

def build_results_message(feed_results, rss_found_already, rss_type):
    res = ""
    
    if feed_results.get("articles"):
        for rss_post in feed_results["articles"]:
            if rss_post['md5'] in rss_found_already['md5s']:
                continue
            if rss_post['link'] in rss_found_already['links']:
                continue
            if rss_post['md5'] not in res:
                post_title = rss_post["title"].lower()
                post_summary = rss_post["summary"].lower()
                
                if rss_type == "news":
                    if not any(x in post_title for x in ["cve", "vulnerability"]):
                        res += f"\n{rss_post['title']}\n"
                        res += f" • link: {rss_post['link']}\n"
                        res += f" • md5: {rss_post['md5']}\n"
                        res += f" • keyword(s): {rss_post['keywords']}\n"
                        res += f" • feed: {rss_post['rss_feed_name']}\n"
                        res += f"---EOM---"
                
                elif rss_type == "cve":
                    if ("cve" in post_title) or ("cve" in post_summary):
                        cve_list = []
                        cve_url_list = []
                        
                        cve_regex = r"(CVE-20[0-9]{2}-\d+)"
                        cve_title_results = re.findall(cve_regex, str(rss_post['title']), re.IGNORECASE)
                        cve_summary_results = re.findall(cve_regex, str(rss_post['summary']), re.IGNORECASE)
                        
                        for title_result in cve_title_results:
                            if title_result not in cve_list:
                                cve_list.append(title_result)
                                title_result_addon = ""
                                if title_result in rss_found_already["fixed_cves"]:
                                    title_result_addon += ":already_fixed:"
                                elif title_result in rss_found_already["seen_cves"]:
                                    title_result_addon += ":already_seen:"
                                cve_url_list.append(
                                    f"<https://cve.mitre.org/cgi-bin/cvename.cgi?name={title_result}|{title_result} {title_result_addon}>"
                                )
                        
                        for summary_result in cve_summary_results:
                            if summary_result not in cve_list:
                                cve_list.append(summary_result)
                                summary_result_addon = ""
                                if summary_result in rss_found_already["fixed_cves"]:
                                    summary_result_addon += ":already_fixed:"
                                elif summary_result in rss_found_already["seen_cves"]:
                                    summary_result_addon += ":already_seen:"
                                cve_url_list.append(
                                    f"<https://cve.mitre.org/cgi-bin/cvename.cgi?name={summary_result}|{summary_result} {summary_result_addon}>"
                                )
                        
                        cve_url_list = str(cve_url_list).strip("[]").replace("'", "")
                        
                        res += f"\n{rss_post['title']}\n"
                        if rss_post['summary']:
                            res += f" • summary: {clean_html(str(rss_post['summary']))}\n"
                        if cve_url_list:
                            res += f" • cve(s): {cve_url_list}\n"
                        res += f" • link: {rss_post['link']}\n"
                        res += f" • md5: {rss_post['md5']}\n"
                        res += f" • keyword(s): {rss_post['keywords']}\n"
                        res += f" • feed: {rss_post['rss_feed_name']}\n"
                        res += f"---EOM---"
    
    return res

def send_message(job_type, message_params, matched, errors, check_stale_keywords=None):
    if str(message_params["slack_enabled"]).lower() == "false":
        logger.debug("Debug: Slack not enabled.")
        return None
    
    slack_token = message_params["slack_token"]
    slack_channel = message_params["channels"]
    pages_to_read = message_params["pages_to_read"]
    
    if slack_token:
        slack_client = init_slack_client(slack_token)
        rss_found = read_channel(slack_client, slack_channel[job_type], job_type, pages_to_read)
        message_body = build_results_message(matched, rss_found, job_type)
        if message_body:
            post_message(slack_client, slack_channel[job_type], message_body)
        
        error_message_body = ""
        if errors:
            error_message_body += "The following feeds are no longer publishing articles:\n"
            for feed in errors:
                error_message_body += f"{str(feed)}\n"
            error_message_body += "\n"
        
        if check_stale_keywords is not None:
            error_message_body += f"Keyword list was last updated on: {str(check_stale_keywords)}\n"
            error_message_body += "Keyword list is over 90 days old and needs to be updated.\n\n"
        
        if error_message_body:
            post_message(slack_client, slack_channel["error"], error_message_body)
    else:
        msg = f"Warning: No Slack token set. No {job_type} items will be posted to Slack."
        logger.warning(msg)
