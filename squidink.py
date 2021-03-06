#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Psychedelic Squid <psquid@psquid.net>
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
# 
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from flask import Flask, redirect, url_for, session, request, render_template, g, make_response, escape, flash
from werkzeug.contrib.securecookie import SecureCookie
from redis import Redis
from hashlib import md5, sha512
import markdown
from datetime import datetime
import random
import re
import PyRSS2Gen
import json
import os
import glob
try:
    import statusnet
    has_statusnet = True
except ImportError:
    import sys
    sys.stderr.write("No statusnet module present. This instance of SquidInk will not emit new post updates to status.net.")
    has_statusnet = False
try:
    import pygments, pygments.lexers, pygments.formatters
    has_pygments = True
except ImportError:
    import sys
    sys.stderr.write("Pygments not present. This instance of SquidInk will not do smart code highlighting.")
    has_pygments = False
app = Flask(__name__)


## UTILITY FUNCTIONS/VARS

config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
try:
    config = json.loads(open(config_path, "r").read())
    KEY_BASE = config["key_base"]
    FANCY_TIME_FMT = config["fancy_time_fmt"]
except:
    KEY_BASE = "squidink:"  # change this to switch default db name; this allows multiple blogs on one redis instance
    FANCY_TIME_FMT = "%H:%M on %a %b %d %Y (UTC)"  # change this to change how times are displayed by default
    open(config_path, "w").write(json.dumps({
        "key_base": KEY_BASE,
        "fancy_time_fmt": FANCY_TIME_FMT
        }, sort_keys=True, indent=4))

TIME_FMT = "%Y-%m-%dT%H:%M:%SZ"
NONCE_CHARS = [chr(c) for c in xrange(ord("A"), ord("Z")+1)]
NONCE_CHARS.extend([chr(c) for c in xrange(ord("a"), ord("z")+1)])
NONCE_CHARS.extend([chr(c) for c in xrange(ord("0"), ord("9")+1)])

@app.before_request
def prepare_globals():
    g.has_statusnet = has_statusnet
    g.has_pygments = has_pygments
    g.db = Redis()
    g.site_name = g.db.get(KEY_BASE+"sitename") or "Unnamed SquidInk app"
    g.theme = g.db.get(KEY_BASE+"theme") or "ink_n_mustard"
    g.themes = {}
    for theme_dir in glob.glob(os.path.join("templates", "*")):
        theme_basename = os.path.basename(theme_dir)
        details_path = os.path.join(theme_dir, "details.json")
        if os.path.exists(details_path):
            theme_details = json.loads(open(details_path).read())
        else:
            theme_details = {}
        if "title" in theme_details:
            g.themes[theme_basename] = theme_details["title"]
        else:
            g.themes[theme_basename] = theme_basename
    g.new_session_cookie_data = None  # this won't be set unless it's needed
    if "username" in session:
        g.username = session["username"]
        g.logged_in = True
    else:
        valid_session = False
        if "saved_session" in request.cookies:
            saved_session = SecureCookie.unserialize(request.cookies["saved_session"], app.secret_key)
            username, series, token = saved_session["user"], saved_session["series"], saved_session["token"]
            if g.db.sismember(KEY_BASE+"users", username):
                if g.db.sismember(KEY_BASE+"users:{0}:sessions".format(username), series):
                    if token == g.db.get(KEY_BASE+"users:{0}:session:{1}:next_token".format(username, series)):
                        g.username = username
                        session["username"] = username
                        g.logged_in = True
                        valid_session = True
                        new_token = build_nonce(32)
                        g.new_session_cookie_data = {
                                "user": username,
                                "series": series,
                                "token": new_token
                                }
                        g.db.setex(KEY_BASE+"users:{0}:session:{1}:next_token".format(username, series), new_token, 40*24*60*60)
                    else:  # We got a valid series, but wrong ID. Statistically it's pretty unlikely the series and username will be correct, but token wrong, unless the cookie is old (I think it would be prudent to assume this may be because it was stolen, à la Firesheep).
                        g.db.delete(KEY_BASE+"users:{0}:sessions".format(username))  # assume the worst, and invalidate all saved sessions
                        for key in g.db.keys(KEY_BASE+"users:{0}:session:*".format(username)):
                            g.db.delete(key)
        if not valid_session:
            g.username = ""
            g.logged_in = False
    g.nav = [
        {"text": "Home", "href": "/"},
        ]
    for page_slug in list(g.db.smembers(KEY_BASE+"pages")):
        if g.db.get(KEY_BASE+"page:{0}:skip_listing".format(page_slug)) is None:
            g.nav.append({
                "text": g.db.get(KEY_BASE+"page:{0}:title".format(page_slug)),
                "href": url_for("show_page", page_slug=page_slug)
                })
    g.sidebar_sections = []
    for sidebar_section in list(g.db.smembers(KEY_BASE+"sidebar:sections")):
        items = []
        for sidebar_item in list(g.db.smembers(KEY_BASE+"sidebar:section:{0}:links".format(sidebar_section))):
            items.append({
                "text": g.db.get(KEY_BASE+"sidebar:section:{0}:link:{1}:title".format(sidebar_section, sidebar_item)),
                "href": g.db.get(KEY_BASE+"sidebar:section:{0}:link:{1}:url".format(sidebar_section, sidebar_item)),
                "id": sidebar_item
                })
        g.sidebar_sections.append({
            "title": g.db.get(KEY_BASE+"sidebar:section:{0}:title".format(sidebar_section)),
            "links": items,
            "id": sidebar_section
            })
    g.current_url = request.path
    if g.db.sismember(KEY_BASE+"admins", g.username):
        g.user_is_admin = True
        g.md = markdown.Markdown()
        if g.has_pygments:
            g.md.parser.blockprocessors.insert(0, "pygmentize", CodeBlockPygmentizer())
    else:
        g.user_is_admin = False
    g.sn = None
    if g.has_statusnet:
        sn_api_url = g.db.get(KEY_BASE+"statusnet:api_url")
        if sn_api_url is not None:
            g.sn_username = g.db.get(KEY_BASE+"statusnet:username")
            g.sn_domain = sn_api_url.replace("https://", "").replace("http://", "").replace("/api", "")
            if g.user_is_admin:  # don't bother setting up the whole object in non-admin sessions, since it won't be used anyway
                sn_password = g.db.get(KEY_BASE+"statusnet:password")
                if g.sn_username is not None and sn_password is not None:
                    try:
                        g.sn = statusnet.StatusNet(sn_api_url, g.sn_username, sn_password)
                    except:
                        pass

@app.after_request
def tidy_response(response):  # do some general housekeeping of the response
    if g.new_session_cookie_data is not None:
        new_session_cookie = SecureCookie(g.new_session_cookie_data, app.secret_key)
        response.set_cookie("saved_session", new_session_cookie.serialize(), max_age=int(30*24*60*60))
    return response

@app.route("/favicon.ico")
def redirect_favicon():
    return redirect(url_for("static", filename=os.path.join(g.theme, "favicon.ico")))

def build_nonce(nonce_length=32):
    nonce = ""
    for index in xrange(nonce_length):
        nonce += random.choice(NONCE_CHARS)
    return nonce

def password_hash(password, per_user_salt=None):  # we do this here so we can change the hash method throughout if necessary
    if per_user_salt is None:  # this user has no salt, due to not having been updated to the new hashing method, so use md5 (user will be moved to new hashing method once they successfully login
        return md5(md5(password).hexdigest()).hexdigest()
    else:
        global_salt = g.db.get(KEY_BASE+"global_salt")
        if global_salt is None:  # we've never used a global salt before, so we must be hashing/re-hashing a password to store
            global_salt = build_nonce(64)  # build global salt, which we will then use
            g.db.set(KEY_BASE+"global_salt", global_salt)  # then store it, so we can get the same salt back later
        return sha512(password + per_user_salt + global_salt).hexdigest()

def is_valid_entity_name(entity_name):  # checks named entities' (users and pages so far) names for valid characters
    RE_VALID_CHARS = re.compile(r"[^A-Za-z0-9_\-.]")  # valid chars regex
    return not bool(RE_VALID_CHARS.search(entity_name))

def format_comment(comment):
    def url_clean(matchobj):
        link_text = matchobj.group(1)
        link_url = matchobj.group(2).replace("&amp;", "&")
        return "<a href=\"{1}\" rel=\"nofollow\">{0}</a>".format(link_text, link_url)
    def user_link(matchobj):
        plain_text = matchobj.group(0)
        username = matchobj.group(1)
        if g.db.sismember(KEY_BASE+"users", username):
            return "[{0}]({1})".format(plain_text, url_for("show_user", username=username))
        else:
            return plain_text
    RE_STRONGEM = re.compile(r"[_*]{3}(.+?)[_*]{3}")
    RE_STRONG = re.compile(r"[_*]{2}(.+?)[_*]{2}")
    RE_EM = re.compile(r"[_*](.+?)[_*]")
    RE_LINK = re.compile(r"\[(.+?)\]\(((http[s]?|/).+?)\)")
    RE_URL = re.compile(r"([^(\[])(http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*,]|(?:%[0-9a-fA-F][0-9a-fA-F]))+)([^)\]])")  # the opening and closing bits are to avoid matching urls already enclosed in []() links
    RE_USER = re.compile(r"@(\w+)")
    comment = escape(comment.replace("\r\n", "\n"))
    # split comment into paragraphs
    comment = "<p>"+"</p>\n<p>".join(comment.split("\n\n"))+"</p>\n"
    # apply strong and em formatting
    comment = RE_STRONGEM.sub("<strong><em>\\1</em></strong>", comment)
    comment = RE_STRONG.sub("<strong>\\1</strong>", comment)
    comment = RE_EM.sub("<em>\\1</em>", comment)
    # add extra spaces to stop RE_URL eating the tags
    for tag in ["p", "strong", "em"]:
        comment = comment.replace("<{0}>".format(tag), " <{0}> ".format(tag))
        comment = comment.replace("</{0}>".format(tag), " </{0}> ".format(tag))
    # turn bare urls into proper link syntax
    comment = RE_URL.sub("\\1[\\2](\\2)\\3", comment)
    # and now remove the spaces
    for tag in ["p", "strong", "em"]:
        comment = comment.replace(" <{0}> ".format(tag), "<{0}>".format(tag))
        comment = comment.replace(" </{0}> ".format(tag), "</{0}>".format(tag))
    # convert @username into user link (but only for existent users)
    comment = RE_USER.sub(user_link, comment)
    # convert links in [text](url) format into HTML links, also cleaning up any weirdness caused by escape earlier
    comment = RE_LINK.sub(url_clean, comment)
    return comment

class CodeBlockPygmentizer(markdown.blockprocessors.BlockProcessor):  # adapted from the Pygments team's preprocessor <https://bitbucket.org/birkenfeld/pygments-main/src/7c7374e6ba50/external/markdown-processor.py>
    codeblock_pattern = re.compile(r"\[code(|:.+?)\](.+?)\[/code\]", re.S)

    def test(self, parent, block):
        return block.strip().startswith("[code")

    def run(self, parent, blocks):
        formatter = pygments.formatters.HtmlFormatter(noclasses=False)
        combined_blocks = []
        def pygmentize_block(match):
            try:
                if match.group(1) == "":
                    lexer = pygments.lexers.TextLexer()
                else:
                    lexer = pygments.lexers.get_lexer_by_name(match.group(1)[1:])
            except ValueError:
                lexer = pygments.lexers.TextLexer()
            code_block = pygments.highlight(match.group(2).rstrip(), lexer, formatter).replace("\n\n", "\n&nbsp;\n").replace("\n", "<br />")
            for original, substitution in {"_": "&#95;", "*": "&#42;"}.items():
                code_block = code_block.replace(original, substitution)
            code_block = code_block.replace("</div><br />", "</div>")
            return "<div class=\"code\">{0}</div>".format(code_block)
        while self.codeblock_pattern.search("\n".join(combined_blocks)) is None:
            combined_blocks.append(blocks.pop(0))
        g.md.parser.parseChunk(parent, self.codeblock_pattern.sub(pygmentize_block, "\n\n".join(combined_blocks).strip()))


### POSTS

@app.route("/")
@app.route("/posts/<int:page_num>")
def show_posts(page_num=1):
    posts_per_page = int(request.args.get("per_page", 10))
    tag = request.args.get("tags", "")
    tag_combine_method = request.args.get("combine", "all")
    if tag_combine_method not in ["any", "all"]:
        tag_combine_method = "all"

    if tag != "":
        tags = tag.split(":")
        post_ids = set([int(id) for id in g.db.zrange(KEY_BASE+"tag:{0}:posts".format(tags[0]), 0, -1)])
        if len(tags) > 1:  # if that wasn't the only tag
            for tag in tags:
                new_post_ids = set([int(id) for id in g.db.zrange(KEY_BASE+"tag:{0}:posts".format(tag), 0, -1)])
                if tag_combine_method == "all":
                    post_ids &= new_post_ids
                elif tag_combine_method == "any":
                    post_ids |= new_post_ids
        post_ids = sorted(list(post_ids), reverse=True)[0+(posts_per_page*(page_num-1)):posts_per_page+(posts_per_page*(page_num-1))]
    else:
        post_ids = [int(id) for id in g.db.lrange(KEY_BASE+"posts", 0+(posts_per_page*(page_num-1)), (posts_per_page-1)+(posts_per_page*(page_num-1)))]

    posts = []

    persist_args = {}
    for arg_name in ["per_page", "tag", "combine"]:
        if arg_name in request.args:
            persist_args[arg_name] = request.args[arg_name]

    if page_num > 1:
        nav_newer = url_for("show_posts", page_num=page_num-1, **persist_args)
    else:
        nav_newer = None

    if page_num * posts_per_page < g.db.llen(KEY_BASE+"posts"):
        nav_older = url_for("show_posts", page_num=page_num+1, **persist_args)
    else:
        nav_older = None

    for id in post_ids:
        posts.append({
            "title": g.db.get(KEY_BASE+"post:{0}:title".format(id)),
            "body": g.db.get(KEY_BASE+"post:{0}:body".format(id)),
            "author": g.db.get(KEY_BASE+"post:{0}:author".format(id)),
            "timestamp": g.db.get(KEY_BASE+"post:{0}:timestamp".format(id)),
            "fancytime": datetime.strptime(g.db.get(KEY_BASE+"post:{0}:timestamp".format(id)), TIME_FMT).strftime(FANCY_TIME_FMT),
            "id": id,
            "num_comments": g.db.llen(KEY_BASE+"post:{0}:comments".format(id)),
            "tags": list(g.db.smembers(KEY_BASE+"post:{0}:tags".format(id))),
            })

    return render_template(os.path.join(g.theme, "posts.html"), title="", posts=posts,
            nav_newer=nav_newer, nav_older=nav_older, multi_post=True)

@app.route("/rss")
def rss_posts():
    posts_per_page = int(request.args.get("per_page", 10))
    tag = request.args.get("tags", "")
    tag_combine_method = request.args.get("combine", "all")
    if tag_combine_method not in ["any", "all"]:
        tag_combine_method = "all"

    if tag != "":
        tags = tag.split(":")
        post_ids = set([int(id) for id in g.db.zrange(KEY_BASE+"tag:{0}:posts".format(tags[0]), 0, -1)])
        if len(tags) > 1:  # if that wasn't the only tag
            for tag in tags:
                new_post_ids = set([int(id) for id in g.db.zrange(KEY_BASE+"tag:{0}:posts".format(tag), 0, -1)])
                if tag_combine_method == "all":
                    post_ids &= new_post_ids
                elif tag_combine_method == "any":
                    post_ids |= new_post_ids
        post_ids = sorted(list(post_ids), reverse=True)[0:posts_per_page]
    else:
        post_ids = [int(id) for id in g.db.lrange(KEY_BASE+"posts", 0, posts_per_page-1)]

    posts = []

    for post_id in post_ids:
        posts.append(
                PyRSS2Gen.RSSItem(
                    title = g.db.get(KEY_BASE+"post:{0}:title".format(post_id)),
                    link = url_for("show_post", post_id=post_id),
                    description = g.db.get(KEY_BASE+"post:{0}:body".format(post_id)),
                    guid = PyRSS2Gen.Guid(url_for("show_post", post_id=post_id)),
                    pubDate = datetime.strptime(g.db.get(KEY_BASE+"post:{0}:timestamp".format(post_id)), TIME_FMT)
                    )
                )

    response = make_response(PyRSS2Gen.RSS2(
            title = g.site_name, link=url_for("show_posts"),
            description = "{0} latest items".format(g.site_name),
            lastBuildDate = datetime.utcnow(),
            items = posts).to_xml())
    response.mimetype = "application/rss+xml"
    return response

@app.route("/post/new", methods=['GET', 'POST'])
def new_post():
    if g.user_is_admin:
        if request.method == "POST":
            new_post_id = g.db.incr(KEY_BASE+"post:next_id")
            g.db.set(KEY_BASE+"post:{0}:title".format(new_post_id), request.form["title"])
            g.db.set(KEY_BASE+"post:{0}:body".format(new_post_id), g.md.convert(request.form["body"]))
            g.db.set(KEY_BASE+"post:{0}:source".format(new_post_id), request.form["body"])
            g.db.set(KEY_BASE+"post:{0}:author".format(new_post_id), g.username)
            g.db.set(KEY_BASE+"post:{0}:timestamp".format(new_post_id), datetime.utcnow().strftime(TIME_FMT))
            tags = [tag.strip().lower() for tag in request.form["tags"].replace(":","").split(",") if tag != ""]
            for tag in tags:
                g.db.sadd(KEY_BASE+"post:{0}:tags".format(new_post_id), tag)
                g.db.zadd(KEY_BASE+"tag:{0}:posts".format(tag), new_post_id, new_post_id)  # add post_id to tag's post sorted list, with itself as the key
            g.db.lpush(KEY_BASE+"users:{0}:posts".format(g.username), new_post_id)
            g.db.lpush(KEY_BASE+"posts", new_post_id)
            if g.sn:
                preamble = "New blog post:"
                post_url = url_for("show_post", post_id=new_post_id, _external=True)
                title = request.form["title"].strip()
                if g.sn.length_limit != 0:
                    remaining_len = 140 - (len(preamble) + len(post_url) + 2)
                    if len(title) > remaining_len:
                        title = title[:remaining_len-3].rstrip() + "..."
                status = "{0} {1} {2}".format(preamble, title, post_url)
                try:
                    result = g.sn.statuses_update(status, source="SquidInk")
                    try:
                        g.db.set(KEY_BASE+"post:{0}:sn_notice_id".format(new_post_id), result["id"])
                    except KeyError:  # no id, must have been an error response
                        pass  # we'll ignore it. TODO: better handling for error responses
                except:  # failed to post at all.
                    pass  # ignore that, too.
            return redirect(url_for("show_post", post_id=new_post_id))
        else:
            return render_template(os.path.join(g.theme, "page_post_edit.html"),
                    action_name="Create post", action_url=url_for("new_post"),
                    is_page=False)
    else:
        return render_template(os.path.join(g.theme, "full_page.html"), title="Not allowed",
                page={
                    "title": "Error",
                    "body": g.md.convert("You are not allowed to create posts.")
                    }), 403

@app.route("/post/<int:post_id>/edit", methods=['GET', 'POST'])
def edit_post(post_id):
    if g.user_is_admin:
        if g.db.get(KEY_BASE+"post:{0}:title".format(post_id)) is not None:
            if request.method == "POST":
                g.db.set(KEY_BASE+"post:{0}:title".format(post_id), request.form["title"])
                g.db.set(KEY_BASE+"post:{0}:body".format(post_id), g.md.convert(request.form["body"]))
                g.db.set(KEY_BASE+"post:{0}:source".format(post_id), request.form["body"])
                g.db.set(KEY_BASE+"post:{0}:edit_timestamp".format(post_id), datetime.utcnow().strftime(TIME_FMT))
                new_tags = [tag.strip().lower() for tag in request.form["tags"].replace(":","").split(",") if tag != ""]
                old_tags = list(g.db.smembers(KEY_BASE+"post:{0}:tags".format(post_id)))
                g.db.delete(KEY_BASE+"post:{0}:tags".format(post_id))  # clear out old tags
                for old_tag in old_tags:  # and remove this post from tag lists it's no longer in
                    if old_tag not in new_tags:
                        g.db.zrem(KEY_BASE+"tag:{0}:posts".format(old_tag), post_id)
                for new_tag in new_tags:
                    g.db.sadd(KEY_BASE+"post:{0}:tags".format(post_id), new_tag)
                    g.db.zadd(KEY_BASE+"tag:{0}:posts".format(new_tag), post_id, post_id)  # add post_id to tag's post sorted list, with itself as the key
                return redirect(url_for("show_post", post_id=post_id))
            else:
                return render_template(os.path.join(g.theme, "page_post_edit.html"),
                        action_name="Edit post", action_url=url_for("edit_post", post_id=post_id),
                        is_page=False,
                        preset_title=g.db.get(KEY_BASE+"post:{0}:title".format(post_id)),
                        preset_body=g.db.get(KEY_BASE+"post:{0}:source".format(post_id)),
                        preset_tags=", ".join(list(g.db.smembers(KEY_BASE+"post:{0}:tags".format(post_id)))))
        else:
            return render_template(os.path.join(g.theme, "full_page.html"), title="Post not found",
                    page={
                        "title": "Error",
                        "body": g.md.convert("No such post exists.")
                        }), 404
    else:
        return render_template(os.path.join(g.theme, "full_page.html"), title="Not allowed",
                page={
                    "title": "Error",
                    "body": g.md.convert("You are not allowed to edit posts.")
                    }), 403

@app.route("/post/<int:post_id>/delete", methods=['GET', 'POST'])
def delete_post(post_id):
    if g.user_is_admin:
        if g.db.get(KEY_BASE+"post:{0}:title".format(post_id)) is not None:
            if request.method == "POST":
                confirm_nonce = request.form["confirm_nonce"]
                stored_nonce = g.db.get(KEY_BASE+"post:{0}:delete_nonce".format(post_id))
                if confirm_nonce == stored_nonce:
                    tags = list(g.db.smembers(KEY_BASE+"post:{0}:tags".format(post_id)))
                    for tag in tags:  # remove this post from tag lists it was in
                        g.db.zrem(KEY_BASE+"tag:{0}:posts".format(tag), post_id)
                    author = g.db.get(KEY_BASE+"post:{0}:author".format(post_id))
                    g.db.lrem(KEY_BASE+"users:{0}:posts".format(author), post_id)
                    for key in g.db.keys(KEY_BASE+"post:{0}:*".format(post_id)):
                        g.db.delete(key)
                    g.db.lrem(KEY_BASE+"posts", post_id, 0)
                    return redirect(url_for("show_posts"))
                elif stored_nonce is not None:
                    return render_template(os.path.join(g.theme, "full_page.html"), title="Bad delete request",
                            page={
                                "title": "Error",
                                "body": g.md.convert("Delete request contained invalid confirmation code.")
                                }), 403
                else:
                    return render_template(os.path.join(g.theme, "full_page.html"), title="Bad delete request",
                            page={
                                "title": "Error",
                                "body": g.md.convert("Delete request expired.")
                                }), 403
            else:
                confirm_nonce = build_nonce()
                g.db.setex(KEY_BASE+"post:{0}:delete_nonce".format(post_id), confirm_nonce, 60)
                return render_template(os.path.join(g.theme, "item_delete.html"), item_type="post", item_title=g.db.get(KEY_BASE+"post:{0}:title".format(post_id)),
                        action_name="Delete post", action_url=url_for("delete_post", post_id=post_id),
                        confirm_nonce=confirm_nonce)
        else:
            return render_template(os.path.join(g.theme, "full_page.html"), title="Post not found",
                    page={
                        "title": "Error",
                        "body": g.md.convert("No such post exists.")
                        }), 404
    else:
        return render_template(os.path.join(g.theme, "full_page.html"), title="Not allowed",
                page={
                    "title": "Error",
                    "body": g.md.convert("You are not allowed to delete posts.")
                    }), 403

@app.route("/post/<int:post_id>/comment", methods=['POST'])
def post_comment(post_id):
    if g.logged_in:
        if request.form["comment"].strip() != "":
            new_comment_id = g.db.incr(KEY_BASE+"post:{0}:comment:next_id".format(post_id))
            g.db.set(KEY_BASE+"post:{0}:comment:{1}:author".format(post_id, new_comment_id), g.username)
            g.db.set(KEY_BASE+"post:{0}:comment:{1}:text".format(post_id, new_comment_id), format_comment(request.form["comment"]))
            g.db.set(KEY_BASE+"post:{0}:comment:{1}:timestamp".format(post_id, new_comment_id), datetime.utcnow().strftime(TIME_FMT))
            g.db.rpush(KEY_BASE+"post:{0}:comments".format(post_id), new_comment_id)
            g.db.lpush(KEY_BASE+"users:{0}:comments".format(g.username), "{0}:{1}".format(post_id, new_comment_id))
            return redirect(url_for("show_post", post_id=post_id)+"#comment-{0}".format(new_comment_id))
        else:
            return redirect(url_for("show_post", post_id=post_id, comment_error="Comments cannot be empty.")+"#new-comment")
    else:
        flash("You must be logged in to comment.")
        return redirect(url_for("login", return_to=url_for("show_post", post_id=post_id, comment=request.form["comment"])+"#new-comment"))

@app.route("/post/<int:post_id>/comment/<int:comment_id>/delete", methods=["POST", "GET"])
def delete_comment(post_id, comment_id):
    if g.user_is_admin:
        if g.db.get(KEY_BASE+"post:{0}:comment:{1}:author".format(post_id, comment_id)) is not None:
            if request.method == "POST":
                confirm_nonce = request.form["confirm_nonce"]
                stored_nonce = g.db.get(KEY_BASE+"post:{0}:comment:{1}:delete_nonce".format(post_id, comment_id))
                if confirm_nonce == stored_nonce:
                    for key in g.db.keys(KEY_BASE+"post:{0}:comment:{1}:*".format(post_id, comment_id)):
                        g.db.delete(key)
                    g.db.lrem(KEY_BASE+"post:{0}:comments".format(post_id), comment_id, 0)
                    return redirect(url_for("show_post", post_id=post_id)+"#comments")
                elif stored_nonce is not None:
                    return render_template(os.path.join(g.theme, "full_page.html"), title="Bad delete request",
                            page={
                                "title": "Error",
                                "body": g.md.convert("Delete request contained invalid confirmation code.")
                                }), 403
                else:
                    return render_template(os.path.join(g.theme, "full_page.html"), title="Bad delete request",
                            page={
                                "title": "Error",
                                "body": g.md.convert("Delete request expired.")
                                }), 403
            else:
                confirm_nonce = build_nonce()
                g.db.setex(KEY_BASE+"post:{0}:comment:{1}:delete_nonce".format(post_id, comment_id), confirm_nonce, 60)
                return render_template(os.path.join(g.theme, "item_delete.html"), item_type="comment",
                        action_name="Delete comment", action_url=url_for("delete_comment", post_id=post_id, comment_id=comment_id),
                        confirm_nonce=confirm_nonce)
        else:
            return render_template(os.path.join(g.theme, "full_page.html"), title="Comment not found",
                    page={
                        "title": "Error",
                        "body": g.md.convert("No such comment exists.")
                        }), 404
    else:
        return render_template(os.path.join(g.theme, "full_page.html"), title="Not allowed",
                page={
                    "title": "Error",
                    "body": g.md.convert("You are not allowed to delete comments.")
                    }), 403

@app.route("/post/<int:post_id>")
def show_post(post_id):
    title = g.db.get(KEY_BASE+"post:{0}:title".format(post_id))
    if title is not None:
        comments = []
        for comment_id in g.db.lrange(KEY_BASE+"post:{0}:comments".format(post_id), 0, -1):
            comment_type = g.db.get(KEY_BASE+"post:{0}:comment:{1}:type".format(post_id, comment_id)) or "local"
            comment = {
                "author": g.db.get(KEY_BASE+"post:{0}:comment:{1}:author".format(post_id, comment_id)),
                "timestamp": g.db.get(KEY_BASE+"post:{0}:comment:{1}:timestamp".format(post_id, comment_id)),
                "fancytime": datetime.strptime(g.db.get(KEY_BASE+"post:{0}:comment:{1}:timestamp".format(post_id, comment_id)), TIME_FMT).strftime(FANCY_TIME_FMT),
                "id": comment_id,
                "type": comment_type,
                }
            if comment_type == "statusnet":
                comment["author_url"] = g.db.get(KEY_BASE+"post:{0}:comment:{1}:author_url".format(post_id, comment_id))
                comment["notice_url"] = g.db.get(KEY_BASE+"post:{0}:comment:{1}:notice_url".format(post_id, comment_id))
                comment["text"] = "<p>{0}</p>".format(escape(g.db.get(KEY_BASE+"post:{0}:comment:{1}:text".format(post_id, comment_id))))  # no special formatting in SN notices, so just escape it and pop it in a <p>
            else:
                comment["text"] = g.db.get(KEY_BASE+"post:{0}:comment:{1}:text".format(post_id, comment_id))
            comments.append(comment)
        all_posts = g.db.lrange(KEY_BASE+"posts", 0, -1)
        post_index = all_posts.index(str(post_id))
        if post_index > 0:
            next_id = all_posts[post_index-1]
            print next_id
            nav_newer = {
                    "title": g.db.get(KEY_BASE+"post:{0}:title".format(next_id)),
                    "id": next_id,
                    }
        else:
            nav_newer = None

        if post_index < len(all_posts)-1:
            prev_id = all_posts[post_index+1]
            print prev_id
            nav_older = {
                    "title": g.db.get(KEY_BASE+"post:{0}:title".format(prev_id)),
                    "id": prev_id,
                    }
        else:
            nav_older = None

        sn_notice_id = g.db.get(KEY_BASE+"post:{0}:sn_notice_id".format(post_id))
        sn_api_url = g.db.get(KEY_BASE+"statusnet:api_url")
        if sn_notice_id is not None and sn_api_url is not None:
            sn_notice_url = "{0}/{1}".format(sn_api_url.replace("/api", "/notice"), sn_notice_id)
        else:
            sn_notice_url = None

        return render_template(os.path.join(g.theme, "posts.html"), title=title,
                posts=[{
                    "title": title,
                    "body": g.db.get(KEY_BASE+"post:{0}:body".format(post_id)),
                    "author": g.db.get(KEY_BASE+"post:{0}:author".format(post_id)),
                    "timestamp": g.db.get(KEY_BASE+"post:{0}:timestamp".format(post_id)),
                    "fancytime": datetime.strptime(g.db.get(KEY_BASE+"post:{0}:timestamp".format(post_id)), TIME_FMT).strftime(FANCY_TIME_FMT),
                    "id": post_id,
                    "comments": comments,
                    "num_comments": len(comments),
                    "tags": list(g.db.smembers(KEY_BASE+"post:{0}:tags".format(post_id))),
                    "nav_newer": nav_newer,
                    "nav_older": nav_older,
                    "sn_notice_url": sn_notice_url,
                    }],
                multi_post=False, comment_error=request.args.get("comment_error", None),
                preset_comment=request.args.get("comment", ""))
    else:
        if 0 < post_id < int(g.db.get(KEY_BASE+"post:next_id")):
            return render_template(os.path.join(g.theme, "full_page.html"), title="Post deleted",
                    page={
                        "title": "Error",
                        "body": g.md.convert("Post was deleted.")
                        }), 410
            return "This post was deleted.",
        else:
            return render_template(os.path.join(g.theme, "full_page.html"), title="Post not found",
                    page={
                        "title": "Error",
                        "body": g.md.convert("No such post exists.")
                        }), 404


### PAGES

@app.route("/page/new", methods=['GET', 'POST'])
def new_page():
    if g.user_is_admin:
        if request.method == "POST":
            new_page_slug = request.form["slug"].lower().strip()
            if new_page_slug in ["new", "delete", "edit", ""]:
                return render_template(os.path.join(g.theme, "page_post_edit.html"),
                        action_name="Create page", action_url=url_for("new_page"),
                        is_page=True, error="Invalid page slug.",
                        preset_title=request.form["title"], preset_body=request.form["body"],
                        preset_listpage=(request.form.get("list_page", None) is not None))
            elif not is_valid_entity_name(new_page_slug):
                return render_template(os.path.join(g.theme, "page_post_edit.html"),
                        action_name="Create page", action_url=url_for("new_page"),
                        is_page=True, error="Invalid characters in page slug.",
                        preset_title=request.form["title"], preset_body=request.form["body"],
                        preset_listpage=(request.form.get("list_page", None) is not None))
            elif not g.db.sismember(KEY_BASE+"pages", new_page_slug):
                g.db.set(KEY_BASE+"page:{0}:title".format(new_page_slug), request.form["title"])
                g.db.set(KEY_BASE+"page:{0}:body".format(new_page_slug), g.md.convert(request.form["body"]))
                g.db.set(KEY_BASE+"page:{0}:source".format(new_page_slug), request.form["body"])
                if request.form.get("list_page", None) is None:
                    g.db.set(KEY_BASE+"page:{0}:skip_listing".format(new_page_slug), True)
                g.db.sadd(KEY_BASE+"pages", new_page_slug)
                return redirect(url_for("show_page", page_slug=new_page_slug))
            else:
                return render_template(os.path.join(g.theme, "page_post_edit.html"),
                        action_name="Create page", action_url=url_for("new_page"),
                        is_page=True, error="Page slug already in use.",
                        preset_title=request.form["title"], preset_body=request.form["body"],
                        preset_listpage=(request.form.get("list_page", None) is not None))
        else:
            return render_template(os.path.join(g.theme, "page_post_edit.html"),
                    action_name="Create page", action_url=url_for("new_page"),
                    is_page=True, preset_listpage=True)
    else:
        return render_template(os.path.join(g.theme, "full_page.html"), title="Not allowed",
                page={
                    "title": "Error",
                    "body": g.md.convert("You are not allowed to create pages.")
                    }), 403

@app.route("/page/<page_slug>/edit", methods=['GET', 'POST'])
def edit_page(page_slug):
    if g.user_is_admin:
        if g.db.get(KEY_BASE+"page:{0}:title".format(page_slug)) is not None:
            if request.method == "POST":
                if request.form["slug"].lower() != page_slug.lower() and is_valid_entity_name(request.form["slug"].lower()) and not request.form["slug"].lower() in ["new", "edit", "delete"]:
                    g.db.delete(KEY_BASE+"page:{0}:title".format(page_slug))
                    g.db.delete(KEY_BASE+"page:{0}:body".format(page_slug))
                    g.db.delete(KEY_BASE+"page:{0}:source".format(page_slug))
                    g.db.srem(KEY_BASE+"pages", page_slug)
                    page_slug = request.form["slug"]
                    g.db.sadd(KEY_BASE+"pages", page_slug)
                g.db.set(KEY_BASE+"page:{0}:title".format(page_slug), request.form["title"])
                g.db.set(KEY_BASE+"page:{0}:body".format(page_slug), g.md.convert(request.form["body"]))
                g.db.set(KEY_BASE+"page:{0}:source".format(page_slug), request.form["body"])
                if request.form.get("list_page", None) is not None:
                    g.db.delete(KEY_BASE+"page:{0}:skip_listing".format(page_slug))
                else:
                    g.db.set(KEY_BASE+"page:{0}:skip_listing".format(page_slug), True)
                return redirect(url_for("show_page", page_slug=page_slug))
            else:
                return render_template(os.path.join(g.theme, "page_post_edit.html"),
                        action_name="Edit page", action_url=url_for("edit_page", page_slug=page_slug),
                        is_page=True,
                        preset_title=g.db.get(KEY_BASE+"page:{0}:title".format(page_slug)),
                        preset_slug=page_slug, preset_listpage=(g.db.get(KEY_BASE+"page:{0}:skip_listing".format(page_slug)) is None),
                        preset_body=g.db.get(KEY_BASE+"page:{0}:source".format(page_slug)))
        else:
            return render_template(os.path.join(g.theme, "full_page.html"), title="Page not found",
                    page={
                        "title": "Error",
                        "body": g.md.convert("No such page exists.")
                        }), 404
    else:
        return render_template(os.path.join(g.theme, "full_page.html"), title="Not allowed",
                page={
                    "title": "Error",
                    "body": g.md.convert("You are not allowed to edit pages.")
                    }), 403

@app.route("/page/<page_slug>/delete", methods=['GET', 'POST'])
def delete_page(page_slug):
    if g.user_is_admin:
        if g.db.get(KEY_BASE+"page:{0}:title".format(page_slug)) is not None:
            if request.method == "POST":
                confirm_nonce = request.form["confirm_nonce"]
                stored_nonce = g.db.get(KEY_BASE+"page:{0}:delete_nonce".format(page_slug))
                if confirm_nonce == stored_nonce:
                    for key in g.db.keys(KEY_BASE+"page:{0}:*".format(page_slug)):
                        g.db.delete(key)
                    g.db.srem(KEY_BASE+"pages", page_slug)
                    return redirect(url_for("show_posts"))
                elif stored_nonce is not None:
                    return render_template(os.path.join(g.theme, "full_page.html"), title="Bad delete request",
                            page={
                                "title": "Error",
                                "body": g.md.convert("Delete request contained invalid confirmation code.")
                                }), 403
                else:
                    return render_template(os.path.join(g.theme, "full_page.html"), title="Bad delete request",
                            page={
                                "title": "Error",
                                "body": g.md.convert("Delete request expired.")
                                }), 403
            else:
                confirm_nonce = build_nonce()
                g.db.setex(KEY_BASE+"page:{0}:delete_nonce".format(page_slug), confirm_nonce, 60)
                return render_template(os.path.join(g.theme, "item_delete.html"), item_type="page",
                        action_name="Delete page", action_url=url_for("delete_page", page_slug=page_slug),
                        confirm_nonce=confirm_nonce)
        else:
            return render_template(os.path.join(g.theme, "full_page.html"), title="Page not found",
                    page={
                        "title": "Error",
                        "body": g.md.convert("No such page exists.")
                        }), 404
    else:
        return render_template(os.path.join(g.theme, "full_page.html"), title="Not allowed",
                page={
                    "title": "Error",
                    "body": g.md.convert("You are not allowed to delete pages.")
                    }), 403

@app.route("/page/<page_slug>")
def show_page(page_slug):
    title = g.db.get(KEY_BASE+"page:{0}:title".format(page_slug))
    if title is not None:
        return render_template(os.path.join(g.theme, "page.html"), title=title,
                page={
                    "title": title,
                    "body": g.db.get(KEY_BASE+"page:{0}:body".format(page_slug)),
                    "slug": page_slug
                    })
    else:
        return render_template(os.path.join(g.theme, "full_page.html"), title="Page not found",
                page={
                    "title": "Error",
                    "body": g.md.convert("No such page exists.")
                    }), 404


### AUTH

@app.route("/login", methods=["GET", "POST"])
def login():
    if not g.logged_in:
        if request.method == "POST":
            try:
                tries = int(g.db.get(KEY_BASE+"users:{0}:pw_tries".format(request.form["username"].lower())))
            except TypeError:
                tries = 0
            if tries >= 5:
                secs_left = g.db.ttl(KEY_BASE+"users:{0}:pw_tries".format(request.form["username"].lower()))
                min_left, secs_left = (secs_left - (secs_left % 60))/60, secs_left % 60
                return render_template(os.path.join(g.theme, "login_register.html"),
                        action_name="Login", action_url=url_for("login"),
                        preset_username=request.form["username"],
                        error="You have used all your tries, and must wait another {0} minute(s), {1} second(s) before any login attempts on this account will be accepted.".format(min_left, secs_left))
            hashed_stored_pw = g.db.get(KEY_BASE+"users:{0}:hashed_pw".format(request.form["username"].lower()))
            if hashed_stored_pw is not None:
                per_user_salt = g.db.get(KEY_BASE+"users:{0}:salt".format(request.form["username"].lower()))
                if per_user_salt is None:  # user's hashing needs to be updated
                    old_hashed_request_pw = password_hash(request.form["password"])
                    if old_hashed_request_pw == hashed_stored_pw:  # this is a good login, so update the stored pw
                        per_user_salt = build_nonce(64)  # generate salt
                        g.db.set(KEY_BASE+"users:{0}:salt".format(request.form["username"].lower()), per_user_salt)
                        hashed_request_pw = password_hash(request.form["password"], per_user_salt=per_user_salt)  # generate new pw
                        g.db.set(KEY_BASE+"users:{0}:hashed_pw".format(request.form["username"].lower()), hashed_request_pw)  # and store it
                        hashed_stored_pw = hashed_request_pw  # then set stored to it, so login proceeds as normal
                    else:
                        hashed_request_pw = ""  # not a valid hash, so the hash check will fail as normal
                else:
                    hashed_request_pw = password_hash(request.form["password"], per_user_salt=per_user_salt)

                if hashed_stored_pw == hashed_request_pw:
                    session["username"] = request.form["username"].lower()
                    if request.form.get("remember_me", None) is not None:  # if remember_me checked, generate a saved session
                        series, token = build_nonce(32), build_nonce(32)
                        g.new_session_cookie_data = {
                                "user": session["username"],
                                "series": series,
                                "token": token
                                }
                        g.db.sadd(KEY_BASE+"users:{0}:sessions".format(session["username"]), series)
                        g.db.setex(KEY_BASE+"users:{0}:session:{1}:next_token".format(session["username"], series), token, 40*24*60*60)
                    return redirect(request.form["return_to"])
                else:
                    trues = g.db.incr(KEY_BASE+"users:{0}:pw_tries".format(request.form["username"].lower()))
                    g.db.expire(KEY_BASE+"users:{0}:pw_tries".format(request.form["username"].lower()), 15*60)
                    return render_template(os.path.join(g.theme, "login_register.html"),
                            action_name="Login", action_url=url_for("login"),
                            preset_username=request.form["username"],
                            return_to=request.form["return_to"],
                            error="Incorrect password. You have {0} tries left, after which all attempts to login to this account will be ignored for 15 minutes.".format(5-tries))
            else:
                return render_template(os.path.join(g.theme, "login_register.html"),
                        action_name="Login", action_url=url_for("login"),
                        return_to=request.form["return_to"],
                        error="No such user.")
        else:
            return render_template(os.path.join(g.theme, "login_register.html"),
                    action_name="Login", action_url=url_for("login"),
                    return_to=request.args.get("return_to", url_for("show_posts")))
    else:
        return render_template(os.path.join(g.theme, "full_page.html"), title="Already logged in",
                page={
                    "title": "Error",
                    "body": g.md.convert("You're already logged in.")
                    }), 403

@app.route("/logout")
def logout():
    if g.logged_in:
        del session["username"]
        if "saved_session" in request.cookies:  # invalidate whatever saved session might exist, so we don't get logged into it as soon as we log out
            saved_session = SecureCookie.unserialize(request.cookies["saved_session"], app.secret_key)
            series = saved_session["series"]
            g.db.srem(KEY_BASE+"users:{0}:sessions".format(g.username), series)
            for key in g.db.keys(KEY_BASE+"users:{0}:session:{1}:*".format(g.username, series)):
                g.db.delete(key)
        return redirect(request.args.get("return_to", url_for("show_posts")))
    else:
        return render_template(os.path.join(g.theme, "full_page.html"), title="Not logged in",
                page={
                    "title": "Error",
                    "body": g.md.convert("You're not logged in.")
                    }), 403


### SIDEBAR ITEMS

@app.route("/sidebar/section/new", methods=['POST'])
def sidebar_new_section():
    if g.user_is_admin:
        next_section_id = g.db.incr(KEY_BASE+"sidebar:section:next_id")
        g.db.sadd(KEY_BASE+"sidebar:sections", next_section_id)
        g.db.set(KEY_BASE+"sidebar:section:{0}:title".format(next_section_id), request.form["title"])
        return redirect(request.args.get("return_to", url_for("show_config")))
    else:
        return render_template(os.path.join(g.theme, "full_page.html"), title="Not allowed",
                page={
                    "title": "Error",
                    "body": g.md.convert("You are not allowed to add sidebar sections.")
                    }), 403

@app.route("/sidebar/item/new", methods=['POST'])
def sidebar_new_item():
    if g.user_is_admin:
        section_id = request.form["section"]
        if not g.db.sismember(KEY_BASE+"sidebar:sections", section_id):
            return render_template(os.path.join(g.theme, "full_page.html"), title="Bad section",
                    page={
                        "title": "Error",
                        "body": g.md.convert("Selected section invalid, or no section selected.")
                        })
        next_item_id = g.db.incr(KEY_BASE+"sidebar:section:{0}:link:next_id".format(section_id))
        g.db.sadd(KEY_BASE+"sidebar:section:{0}:links".format(section_id), next_item_id)
        g.db.set(KEY_BASE+"sidebar:section:{0}:link:{1}:title".format(section_id, next_item_id), request.form["title"])
        g.db.set(KEY_BASE+"sidebar:section:{0}:link:{1}:url".format(section_id, next_item_id), request.form["url"])
        return redirect(request.args.get("return_to", url_for("show_config")))
    else:
        return render_template(os.path.join(g.theme, "full_page.html"), title="Not allowed",
                page={
                    "title": "Error",
                    "body": g.md.convert("You are not allowed to add sidebar sections.")
                    }), 403


### USERS

@app.route("/config")
def show_config():
    if g.user_is_admin:
        unlisted_pages = []
        for page_slug in list(g.db.smembers(KEY_BASE+"pages")):
            if g.db.get(KEY_BASE+"page:{0}:skip_listing".format(page_slug)) is not None:
                unlisted_pages.append({
                    "text": g.db.get(KEY_BASE+"page:{0}:title".format(page_slug)),
                    "slug": page_slug
                    })
        return render_template(os.path.join(g.theme, "config.html"), users=list(g.db.smembers(KEY_BASE+"users")),
                unlisted_pages=unlisted_pages,
                preset_sn_api_url=g.db.get(KEY_BASE+"statusnet:api_url"),
                preset_sn_username=g.db.get(KEY_BASE+"statusnet:username"),
                preset_sn_password=g.db.get(KEY_BASE+"statusnet:password"))
    elif g.logged_in:
        return render_template(os.path.join(g.theme, "config.html"))
    else:
        flash("You must be logged in to change preferences.")
        return redirect(url_for("login", return_to=url_for("show_config")))

@app.route("/config/password", methods=['POST','GET'])
def change_password():
    if request.method == "POST":
        if g.logged_in:
            per_user_salt = g.db.get(KEY_BASE+"users:{0}:salt".format(g.username))
            old_hash = password_hash(request.form["oldpassword"], per_user_salt)  # if per_user_salt is None, this falls back to old hash, which is what was stored, so all's well
            stored_hash = g.db.get(KEY_BASE+"users:{0}:hashed_pw".format(g.username))
            if old_hash == stored_hash:
                new_pass = request.form["newpassword"].strip()
                if len(new_pass) > 0:
                    if per_user_salt is None:  # if no salt, we need to generate some before hashing the new password
                        per_user_salt = build_nonce(64)  # make it
                        g.db.set(KEY_BASE+"users:{0}:salt".format(g.username), per_user_salt)  # and store it. all done, and hashing can proceed
                    new_hash = password_hash(request.form["newpassword"], per_user_salt=per_user_salt)
                    g.db.set(KEY_BASE+"users:{0}:hashed_pw".format(g.username), new_hash)
                    return render_template(os.path.join(g.theme, "full_page.html"), title="Success",
                            page={
                                "title": "Success!",
                                "body": g.md.convert("Password successfully changed.")
                            })
                else:
                    return render_template(os.path.join(g.theme, "config.html"),
                            password_error="Password cannot be blank.")
            else:
                return render_template(os.path.join(g.theme, "config.html"),
                        password_error="Old password incorrect.")
    else:
        return redirect(url_for("show_config"))

@app.route("/user/new", methods=['GET', 'POST'])
def new_user():
    if request.method == "POST":
        username = request.form["username"].strip().lower()
        if username in ["new", "delete", ""]:  #reserved words, cannot be usernames; empty name also
            return render_template(os.path.join(g.theme, "login_register.html"),
                    action_name="Register", action_url=url_for("new_user"),
                    error="That username is invalid.")
        elif not is_valid_entity_name(username):
            return render_template(os.path.join(g.theme, "login_register.html"),
                    action_name="Register", action_url=url_for("new_user"),
                    error="Username contains invalid characters (alphanumerics only for the username).")
        elif not g.db.sismember(KEY_BASE+"users", username):
            password = request.form["password"].strip()
            if len(password) > 0:
                g.db.sadd(KEY_BASE+"users", username)
                per_user_salt = build_nonce(64)  # generate salt
                g.db.set(KEY_BASE+"users:{0}:salt".format(username), per_user_salt)
                g.db.set(KEY_BASE+"users:{0}:hashed_pw".format(username),
                        password_hash(password, per_user_salt=per_user_salt))
                if "username" in session:
                    return render_template(os.path.join(g.theme, "full_page.html"), title="Success",
                            page={
                                "title": "Success!",
                                "body": g.md.convert("Created user *{0}*.".format(username))
                            })
                else:
                    session["username"] = username
                    if request.form.get("remember_me", None) is not None:  # if remember_me checked, generate a saved session
                        series, token = build_nonce(32), build_nonce(32)
                        g.new_session_cookie_data = {
                                "user": session["username"],
                                "series": series,
                                "token": token
                                }
                        g.db.sadd(KEY_BASE+"users:{0}:sessions".format(session["username"]), series)
                        g.db.setex(KEY_BASE+"users:{0}:session:{1}:next_token".format(session["username"], series), token, 40*24*60*60)
                    return redirect(request.form["return_to"])
            else:
                return render_template(os.path.join(g.theme, "login_register.html"),
                        action_name="Register", action_url=url_for("new_user"),
                        preset_username=username, return_to=request.form["return_to"],
                        error="Password cannot be blank.")
        else:
            return render_template(os.path.join(g.theme, "login_register.html"),
                    action_name="Register", action_url=url_for("new_user"),
                    return_to=request.form["return_to"],
                    error="That username is already taken.")
    else:
        return render_template(os.path.join(g.theme, "login_register.html"),
                action_name="Register", action_url=url_for("new_user"),
                return_to=request.args.get("return_to", url_for("show_posts")))

@app.route("/user/<username>")
def show_user(username):
    if g.db.sismember(KEY_BASE+"users", username):
        latest_posts = []
        for post_id in g.db.lrange(KEY_BASE+"users:{0}:posts".format(username), 0, 4):
            latest_posts.append({
                "title": g.db.get(KEY_BASE+"post:{0}:title".format(post_id)),
                "id": post_id,
                })
        latest_comments_raw = g.db.lrange(KEY_BASE+"users:{0}:comments".format(username), 0, 4)
        latest_comments = []
        for comment in latest_comments_raw:
            post_id, comment_id = comment.split(":")
            text = g.db.get(KEY_BASE+"post:{0}:comment:{1}:text".format(post_id, comment_id))
            if text is not None:  # avoid trying to display deleted comments
                latest_comments.append({
                    "text": text,
                    "timestamp": g.db.get(KEY_BASE+"post:{0}:comment:{1}:timestamp".format(post_id, comment_id)),
                    "fancytime": datetime.strptime(g.db.get(KEY_BASE+"post:{0}:comment:{1}:timestamp".format(post_id, comment_id)), TIME_FMT).strftime(FANCY_TIME_FMT),
                    "post_title": g.db.get(KEY_BASE+"post:{0}:title".format(post_id)),
                    "post_id": post_id,
                    "id": comment_id,
                    })
        return render_template(os.path.join(g.theme, "user.html"), username=username,
                latest_comments=latest_comments, latest_posts=latest_posts)
    else:
        return render_template(os.path.join(g.theme, "full_page.html"), title="User not found",
                page={
                    "title": "Error",
                    "body": g.md.convert("No such user found.")
                    }), 404

@app.route("/user/<username>/delete", methods=['GET', 'POST'])
def delete_user(username):
    if g.user_is_admin:
        if g.db.sismember(KEY_BASE+"users", username):
            if request.method == "POST":
                confirm_nonce = request.form["confirm_nonce"]
                stored_nonce = g.db.get(KEY_BASE+"users:{0}:delete_nonce".format(username))
                if confirm_nonce == stored_nonce:
                    for key in g.db.keys(KEY_BASE+"users:{0}:*".format(username)):
                        g.db.delete(key)
                    g.db.srem(KEY_BASE+"users", username)
                    return redirect(url_for("show_config"))
                elif stored_nonce is not None:
                    return render_template(os.path.join(g.theme, "full_page.html"), title="Bad delete request",
                            page={
                                "title": "Error",
                                "body": g.md.convert("Delete request contained invalid confirmation code.")
                                }), 403
                else:
                    return render_template(os.path.join(g.theme, "full_page.html"), title="Bad delete request",
                            page={
                                "title": "Error",
                                "body": g.md.convert("Delete request expired.")
                                }), 403
            else:
                confirm_nonce = build_nonce()
                g.db.setex(KEY_BASE+"users:{0}:delete_nonce".format(username), confirm_nonce, 60)
                return render_template(os.path.join(g.theme, "item_delete.html"), item_type="user",
                        action_name="Delete user", action_url=url_for("delete_user", username=username),
                        confirm_nonce=confirm_nonce)
        else:
            return render_template(os.path.join(g.theme, "full_page.html"), title="User not found",
                    page={
                        "title": "Error",
                        "body": g.md.convert("No such user found.")
                        }), 404
    else:
        return render_template(os.path.join(g.theme, "full_page.html"), title="Not allowed",
                page={
                    "title": "Error",
                    "body": g.md.convert("You are not allowed to delete this user.")
                    }), 403


### STATUS.NET INTEGRATION

@app.route("/statusnet/config", methods=['POST'])
def sn_set_credentials():
    if g.user_is_admin:
        sn_api_url = request.form["sn_api_url"].strip()
        sn_username = request.form["sn_username"].strip().lower()
        sn_password = request.form["sn_password"].strip()

        if sn_api_url != "":
            g.db.set(KEY_BASE+"statusnet:api_url", sn_api_url)
        else:
            g.db.delete(KEY_BASE+"statusnet:api_url")

        if sn_username != "":
            g.db.set(KEY_BASE+"statusnet:username", sn_username)
        else:
            g.db.delete(KEY_BASE+"statusnet:username")

        if sn_password != "":
            g.db.set(KEY_BASE+"statusnet:password", sn_password)
        else:
            g.db.delete(KEY_BASE+"statusnet:password")

        return redirect(request.args.get("return_to", url_for("show_config")))
    else:
        return render_template(os.path.join(g.theme, "full_page.html"), title="Not allowed",
                page={
                    "title": "Error",
                    "body": g.md.convert("You are not allowed to change status.net access credentials.")
                    }), 403


### THEMING

@app.route("/theme/change", methods=['POST'])
def change_theme():
    if g.user_is_admin:
        theme_path = request.form["theme_path"].lower().strip()
        if theme_path in g.themes:
            g.db.set(KEY_BASE+"theme", theme_path)
            return redirect(request.args.get("return_to", url_for("show_config")))
        else:
            return render_template(os.path.join(g.theme, "full_page.html"), title="No such theme.",
                    page={
                        "title": "Error",
                        "body": g.md.convert("No such theme exists. Maybe it was deleted?")
                        }), 404
    else:
        return render_template(os.path.join(g.theme, "full_page.html"), title="Not allowed",
                page={
                    "title": "Error",
                    "body": g.md.convert("You are not allowed to add change themes.")
                    }), 403


if __name__ == "__main__":
    app.secret_key = ",j\x16!|5@\x8a\xe6&tLt\xd3\xd7\x00s\xaa[|\x89\xee\xe7-"  # required for session use
    app.debug = True
    app.run(host="0.0.0.0", port=5000)
