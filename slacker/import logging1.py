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


def read_channel(client, channel_id, rss_type):
def read_channel(client, channel_id, rss_type, pages_to_read):
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
        # Call the conversations.history method using the WebClient
        # The conversations.history returns 99 messages by default
        # Results are paginated, see: https://api.slack.com/method/conversations.history$pagination
        # TODO handle paginating multiple pages
        conversation_history = []
        result = client.conversations_history(channel=channel_id)
        conversation_history = result["messages"]
        conversation_history.extend(result["messages"])

        while result["response_metadata"]["next_cursor"] is not None and pages_to_read > 0:
          result = client.conversations_history(channel=channel_id, cursor=result["response_metadata"]["next_cursor"])
          conversation_history.extend(result["messages"])
          pages_to_read = pages_to_read - 1

        # Initialize dict and lists for storing links/md5s
        re_link = []
        link_regex = r"(?:link\:.+?)(https?:\/\/(?:www\.)?[-a-zA-Z-1-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&\/=]*))"
        re_results = re.findall(link_regex, str(conversation_history), re.IGNORECASE)
        for re_result in re_results:
            if re_result not in re_link:
                re_link.append(re_result)
        re_md5 = []
        md5_regex = r"(?:md5:\s)([a-f0-9]{32})"
        re_results = re.findall(md5_regex, str(conversation_history), re.IGNORECASE)
        for re_result in re_results:
            if re_result not in re_md5:
                re_md5.append(re_result)
        already_fixed_list = []
        already_seen_list = []
        # Save timestamp if cve
        if rss_type == "cve":
            cve_regex = r"(CVE-20[0-9]{2}-\d+)"
            for dialog in conversation_history:
                if "reactions" in dialog:
                    if list(filter(lambda item: item['name'] == 'white_check_mark', dialog["reactions"])):
                        cve_dialog_results = re.findall(cve_regex, str(dialog), re.IGNORECASE)
                        for dialog_result in cve_dialog_results:
                            if dialog_result not in already_fixed_list:
                                already_fixed_list.append(dialog_result)
            cve_convo_results = re.findall(cve_regex, str(conversation_history), re.IGNORECASE)
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
        msg = f"Error creating conversation: {e}"
        logger.error(msg)
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
