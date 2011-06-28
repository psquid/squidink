#!/usr/bin/env python
import statusnet, json, redis

def notice_datetime(notice):  # handle statusnet's time shenanigans
    import datetime, re, locale
    offset_regex = re.compile("[+-][0-9]{4}")
    DATETIME_FORMAT = "%a %b %d %H:%M:%S +0000 %Y"
    def utc_offset(time_string):
        offset = offset_regex.findall(time_string)[0]
        offset_hours = int(offset[1:3])
        offset_minutes = int(offset[3:])
        return datetime.timedelta(hours=offset_hours,minutes=offset_minutes)
    locale.setlocale(locale.LC_TIME, 'C')  # hacky fix because statusnet uses english timestrings regardless of locale
    created_at_no_offset = offset_regex.sub("+0000", notice['created_at'])
    attempts = 10
    normalised_datetime = None  # this will stay intact if time conversion fails
    while attempts > 0:
        attempts -= 1
        try:
            normalised_datetime = datetime.datetime.strptime(created_at_no_offset, DATETIME_FORMAT) + utc_offset(notice['created_at'])
            break
        except ValueError:  # something else changed the locale, and Python threw a hissy fit
            pass
    locale.setlocale(locale.LC_TIME, '') # other half of the hacky fix
    return normalised_datetime

config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
config = json.loads(open(config_path, "r").read())
KEY_BASE = config["key_base"]

TIME_FMT = "%Y-%m-%dT%H:%M:%SZ"

db = redis.Redis()

sn_api_url = db.get(KEY_BASE+"statusnet:api_url")
sn_username = db.get(KEY_BASE+"statusnet:username")
sn_password = db.get(KEY_BASE+"statusnet:password")
if sn_api_url is not None and sn_username is not None and sn_password is not None:
    sn = statusnet.StatusNet(sn_api_url, sn_username, sn_password)

for post_id in list(db.lrange(KEY_BASE+"posts", 0, -1)):
    broadcast_notice_id = db.get(KEY_BASE+"post:{0}:sn_notice_id".format(post_id))  # get the announcement notice
    if broadcast_notice_id is None:  # skip the post if it wasn't announced
        continue
    last_checked_notice_id = db.get(KEY_BASE+"post:{0}:sn_last_notice_id".format(post_id))
    if last_checked_notice_id is None:
        last_checked_notice_id = broadcast_notice_id  # fall back to the announcement notice if needed

    full_mentions = []
    mentions_page = 1
    while True:
        latest_mentions = sn.statuses_mentions(page=mentions_page, count=20, since_id=last_checked_notice_id)
        full_mentions.extend(latest_mentions)
        if len(latest_mentions) < 20:  # not a full page, so no more to fetch
            break
        else:
            mentions_page += 1

    for notice in full_mentions[::-1]:  # run through them backwards so we get them in chronological order
        if str(notice["id"]) == str(last_checked_notice_id):  # this notice was the last checked one
            continue  # ignore it so we don't get duplicates
        if str(notice.get("in_reply_to_status_id", None)) == str(broadcast_notice_id):
            raw_timestamp = notice_datetime(notice)
            if raw_timestamp is None:  # something's wrong with the notice, or the system. skip this notice
                continue
            new_comment_id = db.incr(KEY_BASE+"post:{0}:comment:next_id".format(post_id))
            db.set(KEY_BASE+"post:{0}:comment:{1}:author".format(post_id, new_comment_id), notice["user"]["screen_name"])
            db.set(KEY_BASE+"post:{0}:comment:{1}:text".format(post_id, new_comment_id), notice["text"])
            db.set(KEY_BASE+"post:{0}:comment:{1}:timestamp".format(post_id, new_comment_id), raw_timestamp.strftime(TIME_FMT))
            db.set(KEY_BASE+"post:{0}:comment:{1}:author_url".format(post_id, new_comment_id), notice["user"]["statusnet_profile_url"])
            db.set(KEY_BASE+"post:{0}:comment:{1}:type".format(post_id, new_comment_id), "statusnet")
            db.rpush(KEY_BASE+"post:{0}:comments".format(post_id), new_comment_id)

    if len(full_mentions) > 0:
        db.set(KEY_BASE+"post:{0}:sn_last_notice_id".format(post_id), full_mentions[0]["id"])  # set last checked so we don't pull comments again
