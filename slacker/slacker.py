import logging
import re
from bs4 import BeautifulSoup
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

# Requires adding slack_sdk to the requirements.txt file
# Requires adding bs4 to the requirements.txt file
# Requires adding lxml to the requirements.txt file

# Set module logger name
logger = logging.getLogger(__name__)


def init_slack_client(slack_token):
    """
    Instantiates a Slack web client that can call API methods

    :param slack_token: Slack API token
    :return: Slack Client Object
    """
    return WebClient(token=slack_token)


<<<<<<< HEAD
def read_channel(client, channel_id, rss_type, pages_to_read: str) -> dict:
    
    
    
=======
def read_channel(client, channel_id, rss_type):
>>>>>>> parent of 2dc8392 (Update pagination function)
    """
    Reads channel conversations and returns matching content

    This requires the following scopes:
      channels:history
        View messages and other content in public channels that syphon has been added to
      groups:history
        View messages and other content in private channels that syphon has been added to
      im:history
        View messages and other content in direct messages that syphon has been added to
      incoming-webhook
        Post messages to specific channels in Slack
      mpim:history
        View messages and other content in group direct messages that syphon has been added to

    :param client: Slack Client Object
    :param channel_id: Slack Channel ID
    :param rss_type: CVE or NEWs job type
    :return: Dictionary of content
    """
    # Set default return dict
    re_dict = {
        "links": [],
        "md5s": [],
        "fixed_cves": [],
        "seen_cves": []
    }

    try:
<<<<<<< HEAD
        # Convert pages_to_read to an integer if it's not already
             
        conversation_history = []
        result = client.conversations_history(channel=channel_id)
        conversation_history.extend(result.get("messages", []))
        
        # Initialize next_cursor safely
        next_cursor = result.get("response_metadata", {}).get("next_cursor")

        while next_cursor and pages_to_read > 0:  # Check if next_cursor is not empty and pages_to_read > 0
          result = client.conversations_history(channel=channel_id, cursor=next_cursor)
          conversation_history.extend(result.get("messages", []))
          pages_to_read -= 1
          # Safely update next_cursor
          next_cursor = result.get("response_metadata", {}).get("next_cursor")
=======
        # Call the conversations.history method using the WebClient
        # The conversations.history returns 99 messages by default
        # Results are paginated, see: https://api.slack.com/method/conversations.history$pagination
        # TODO handle paginating multiple pages
        result = client.conversations_history(channel=channel_id)
        conversation_history = result["messages"]
>>>>>>> parent of 2dc8392 (Update pagination function)

        # Process extracted messages to find links and MD5 hashes
        re_link = []
        link_regex = re.compile(r"(?:link\:.+?)(https?:\/\/(?:www\.)?[-a-zA-Z-1-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&\/=]*))", re.IGNORECASE)
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

        # Save data if job type is CVE
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

        re_dict = {
            "links": re_link,
            "md5s": re_md5,
            "fixed_cves": already_fixed_list,
            "seen_cves": already_seen_list
        }

    except SlackApiError as e:
        msg = f"Error fetching conversation data: {e.response.get('error', 'Unknown error')}"
        logger.error(msg)
        return re_dict
    except KeyError as e:
        # This catches missing keys in the result dictionary
        logger.error(f"Key error: {e} - likely missing in the API response.")
        return re_dict

    return re_dict


def post_message(client, channel_id, messages):
    """
    This requires the following scopes:
      chat:write:bot
        Send messages as @syphon

    :param client: Slack Client Object
    :param channel_id: Slack Channel ID
    :param messages: Message body content
    """
    # messages = message_body.split('\n\n\n\n')
    for message in messages.split('\n---EOM---'):
        if message:
            try:
                # Call the chat.postMessage method using the WebClient
                result = client.chat_postMessage(
                    channel=channel_id,
                    text=message,
                    unfurl_links=False,
                    unfurl_media=False,
                    parse="mrkdwn"
                )
                logger.info(result)
            except SlackApiError as e:
                msg = f"Error posting message: {e}"
                logger.error(msg)


def clean_html(input_text):
    """
    Summaries often come as html formatted.
    This def uses bs4 to clean that up.

    :param input_text: Text to clean
    :return: Cleaned output
    """
    text = BeautifulSoup(input_text, "lxml").get_text(separator="\n")
    return re.sub('\n\n', '\n', text)


def build_results_message(feed_results, rss_found_already, rss_type):
    """
    Build message which will be used as the content body

    :param feed_results: Full list of processed rss posts
    :param rss_found_already: Filter for RSS articles found in Slack channel
    :param rss_type: Limited to News or CVE type articles
    :return: Message body content
    """
    res = ""

    if feed_results["articles"]:
        for rss_post in feed_results["articles"]:
            if rss_post['md5'] in rss_found_already['md5s']:
                continue
            elif rss_post['link'] in rss_found_already['links']:
                continue
            elif rss_post['md5'] not in res:
                post_title = rss_post["title"].lower()
                post_summary = rss_post["summary"].lower()

                # Publishing News
                if rss_type == "news":
                    if not any(x in post_title for x in ["cve", "vulnerability"]):
                        res += f"\n{rss_post['title']}\n"
                        res += f" • link: {rss_post['link']}\n"
                        res += f" • md5: {rss_post['md5']}\n"
                        res += f" • keyword(s): {rss_post['keywords']}\n"
                        res += f" • feed: {rss_post['rss_feed_name']}\n"
                        res += f"---EOM---"

                # Publishing CVEs
                elif rss_type == "cve":
                    if ("cve" in post_title) or ("cve" in post_summary):
                        # Parse for CVEs
                        cve_list = []
                        cve_url_list = []

                        cve_regex = r"(CVE-20[0-9]{2}-\d+)"
                        cve_title_results = re.findall(cve_regex, str(rss_post['title']), re.IGNORECASE)
                        cve_summary_results = re.findall(cve_regex, str(rss_post['summary']), re.IGNORECASE)

                        # Check CVE lists and dedup results and readies for results
                        for title_result in cve_title_results:
                            if title_result not in cve_list:
                                cve_list.append(title_result)
                                title_result_addon = ""
                                if title_result in rss_found_already["fixed_cves"]:
                                    title_result_addon += ":already_fixed:"
                                elif title_result in rss_found_already["seen_cves"]:
                                    title_result_addon += ":already_seen:"
                                cve_url_list.append(
                                    f"<https://cve.mitre.org/cgi-bin/cvename.cgi?name={title_result}|{title_result} {title_result_addon}>")

                        for summary_result in cve_summary_results:
                            if summary_result not in cve_list:
                                cve_list.append(summary_result)
                                summary_result_addon = ""
                                if summary_result in rss_found_already["fixed_cves"]:
                                    summary_result_addon += ":already_fixed:"
                                elif summary_result in rss_found_already["seen_cves"]:
                                    summary_result_addon += ":already_seen:"
                                cve_url_list.append(
                                    f"<https://cve.mitre.org/cgi-bin/cvename.cgi?name={summary_result}|{summary_result} {summary_result_addon}>")

                        # Backslashes not allowed in f-string
                        cve_url_list = str(cve_url_list).strip("[]").replace("\'", "")

                        res += f"\n{rss_post['title']}\n"
                        if rss_post['summary']:
                            res += f" • summary: {clean_html(str(rss_post['summary']))}\n"
                        if cve_url_list:
                            res += f"\n • cve(s): {cve_url_list}\n"
                        res += f" • link: {rss_post['link']}\n"
                        res += f" • md5: {rss_post['md5']}\n"
                        res += f" • keyword(s): {rss_post['keywords']}\n"
                        res += f" • feed: {rss_post['rss_feed_name']}\n"
                        res += f"---EOM---"

    return res


def send_message(job_type, message_params, matched, errors, check_stale_keywords=None):
    """
    Send prepared RSS feed results to Slack

    :param job_type: CVE or NEWs job type
    :param message_params: Dictionary of message config values
    :param matched: Keyword matched RSS articles
    :param errors: List of feeds that have an error
    :param check_stale_keywords: None or date
    """
      
    # Check if module is enabled and bail out if not
    if str(message_params["slack_enabled"]).lower() == "false":
        logger.debug("Debug: Slack not enabled.")
        return None

    slack_token = message_params["slack_token"]
    slack_channel = message_params["channels"]

    try:
        pages_to_read = int(message_params["pages_to_read"])  # Convert pages_to_read to integer
    except ValueError:
        logger.error(f"pages_to_read should be an integer, got: {message_params['pages_to_read']}")
        return  # Exit the function if conversion fails
    
   
    # Check if slack_token is set
    if slack_token:
        # Init Slack Client
        slack_client = init_slack_client(slack_token)

        # Pull RSS that was found already in channel
        rss_found = read_channel(slack_client, slack_channel[job_type], job_type)

        # Build the message that will be sent
        message_body = build_results_message(matched, rss_found, job_type)
        if message_body:
            post_message(slack_client, slack_channel[job_type], message_body)

        # Feeds that have changes or are offline
        error_message_body = ""
        if len(errors) > 0:
            error_message_body += f"The following feeds are no longer publishing articles:\n"
            for feed in errors:
                error_message_body += f"{str(feed)}\n"
            error_message_body += f"\n"

        # Keywords need to be updated
        if check_stale_keywords is not None:
            error_message_body += f"Keyword list was last updated on: {str(check_stale_keywords)}\n"
            error_message_body += f"Keyword list is over 90 days old and needs to be updated.\n\n"

        if error_message_body:
            post_message(slack_client, slack_channel["error"], error_message_body)
    else:
        msg = f"Warning: No Slack token set. No {job_type} items will be posted to Slack."
        logger.warning(msg)
