#!/usr/bin/env python
from flask import Flask, redirect, url_for, session, escape, request, render_template, g, abort, Markup
from redis import Redis
from hashlib import md5
import markdown
from datetime import datetime
import random
import re
app = Flask(__name__)


## UTILITY FUNCTIONS/VARS

KEY_BASE = "squidink:"  # change this to switch db name; this allows multiple blogs on one redis instance
FANCY_TIME_FMT = "%H:%M on %a %b %d %Y (UTC)"  # change this to change how times are displayed

TIME_FMT = "%Y-%m-%dT%H:%M:%SZ"
NONCE_CHARS = [chr(c) for c in xrange(ord("A"), ord("Z")+1)]
NONCE_CHARS.extend([chr(c) for c in xrange(ord("a"), ord("z")+1)])
NONCE_CHARS.extend([chr(c) for c in xrange(ord("0"), ord("9")+1)])

@app.before_request
def prepare_globals():
    g.db = Redis()
    g.md = markdown.Markdown(safe_mode=True)
    g.site_name = g.db.get(KEY_BASE+"sitename") or "Unnamed SquidInk app"
    if "username" in session:
        g.username = session["username"]
        g.logged_in = True
    else:
        g.username = ""
        g.logged_in = False
    g.nav = [
        {"text": "Home", "href": "/"},
        ]
    for page_slug in list(g.db.smembers(KEY_BASE+"pages")):
        g.nav.append({
            "text": g.db.get(KEY_BASE+"page:{0}:title".format(page_slug)),
            "href": url_for("show_page", page_slug=page_slug)
            })
    if g.db.sismember(KEY_BASE+"admins", g.username):
        g.user_is_admin = True
        g.nav.extend([
            {"text": "New post", "href": "/post/new"},
            {"text": "New page", "href": "/page/new"},
            ])
    else:
        g.user_is_admin = False

@app.route("/favicon.ico")
def redirect_favicon():
    return redirect(url_for("static", filename="favicon.ico"))

def build_nonce(nonce_length=32):
    nonce = ""
    for index in xrange(nonce_length):
        nonce += random.choice(NONCE_CHARS)
    return nonce

def format_comment(comment):
    RE_STRONGEM = re.compile("([_*]{3}.+[_*]{3})")
    RE_STRONG = re.compile("([_*]{2}.+[_*]{2})")
    RE_EM = re.compile("([_*].+[_*])")
    formatted_comment = Markup("")
    for para in comment.replace("\r\n", "\n").split("\n\n"):
        formatted_comment += Markup("<p>")
        for block in RE_STRONGEM.split(para):
            if RE_STRONGEM.match(block):
                formatted_comment += Markup("<strong><em>")
                formatted_comment += Markup.escape(block[3:-3])
                formatted_comment += Markup("</em></strong>")
            else:
                for block in RE_STRONG.split(block):
                    if RE_STRONG.match(block):
                        formatted_comment += Markup("<strong>")
                        formatted_comment += Markup.escape(block[2:-2])
                        formatted_comment += Markup("</strong>")
                    else:
                        for block in RE_EM.split(block):
                            if RE_EM.match(block):
                                formatted_comment += Markup("<em>")
                                formatted_comment += Markup.escape(block[1:-1])
                                formatted_comment += Markup("</em>")
                            else:
                                formatted_comment += Markup.escape(block)
        formatted_comment += Markup("</p>\n")
    return formatted_comment

### POSTS

@app.route("/")
@app.route("/posts/<int:page_num>")
def show_posts(page_num=1):
    persist_args = {}
    if "per_page" in request.args:
        persist_args["per_page"] = request.args["per_page"]

    posts_per_page = int(request.args.get("per_page", 10))

    if page_num > 1:
        nav_newer = url_for("show_posts", page_num=page_num-1, **persist_args)
    else:
        nav_newer = None

    if page_num * posts_per_page < g.db.llen(KEY_BASE+"posts"):
        nav_older = url_for("show_posts", page_num=page_num+1, **persist_args)
    else:
        nav_older = None

    post_ids = [int(id) for id in g.db.lrange(KEY_BASE+"posts", 0+(posts_per_page*(page_num-1)), (posts_per_page-1)+(posts_per_page*(page_num-1)))]
    posts = []
    for id in post_ids:
        posts.append({
            "title": g.db.get(KEY_BASE+"post:{0}:title".format(id)),
            "body": g.md.convert(g.db.get(KEY_BASE+"post:{0}:body".format(id))),
            "author": g.db.get(KEY_BASE+"post:{0}:author".format(id)),
            "timestamp": g.db.get(KEY_BASE+"post:{0}:timestamp".format(id)),
            "fancytime": datetime.strptime(g.db.get(KEY_BASE+"post:{0}:timestamp".format(id)), TIME_FMT).strftime(FANCY_TIME_FMT),
            "id": id,
            "num_comments": g.db.llen(KEY_BASE+"post:{0}:comments".format(id))
            })

    return render_template("posts.html", title="", posts=posts,
            nav_newer=nav_newer, nav_older=nav_older, multi_post=True,
            site_name=g.site_name, sidebar_sections=[], navigation=g.nav,
            username=g.username, user_is_admin=g.user_is_admin)

@app.route("/post/new", methods=['GET', 'POST'])
def new_post():
    if g.user_is_admin:
        if request.method == "POST":
            new_post_id = g.db.incr(KEY_BASE+"post:next_id")
            g.db.set(KEY_BASE+"post:{0}:title".format(new_post_id), request.form["title"])
            g.db.set(KEY_BASE+"post:{0}:body".format(new_post_id), request.form["body"])
            g.db.set(KEY_BASE+"post:{0}:author".format(new_post_id), session["username"])
            g.db.set(KEY_BASE+"post:{0}:timestamp".format(new_post_id), datetime.utcnow().strftime(TIME_FMT))
            g.db.lpush(KEY_BASE+"posts", new_post_id)
            return redirect(url_for("show_post", post_id=new_post_id))
        else:
            return render_template("page_post_edit.html",
                    action_name="Create post", action_url=url_for("new_post"),
                    site_name=g.site_name, navigation=g.nav, is_page=False)
    else:
        abort(403)

@app.route("/post/<int:post_id>/edit", methods=['GET', 'POST'])
def edit_post(post_id):
    if g.user_is_admin:
        if g.db.get(KEY_BASE+"post:{0}:title".format(post_id)) is not None:
            if request.method == "POST":
                g.db.set(KEY_BASE+"post:{0}:title".format(post_id), request.form["title"])
                g.db.set(KEY_BASE+"post:{0}:body".format(post_id), request.form["body"])
                g.db.set(KEY_BASE+"post:{0}:edit_timestamp".format(post_id), datetime.utcnow().strftime(TIME_FMT))
                return redirect(url_for("show_post", post_id=post_id))
            else:
                return render_template("page_post_edit.html",
                        action_name="Edit post", action_url=url_for("edit_post", post_id=post_id),
                        site_name=g.site_name, navigation=g.nav, is_page=False,
                        preset_title=g.db.get(KEY_BASE+"post:{0}:title".format(post_id)),
                        preset_body=g.db.get(KEY_BASE+"post:{0}:body".format(post_id)))
        else:
            abort(404)
    else:
        abort(403)

@app.route("/post/<int:post_id>/delete", methods=['GET', 'POST'])
def delete_post(post_id):
    if g.user_is_admin:
        if g.db.get(KEY_BASE+"post:{0}:title".format(post_id)) is not None:
            if request.method == "POST":
                confirm_nonce = request.form["confirm_nonce"]
                stored_nonce = g.db.get(KEY_BASE+"post:{0}:delete_nonce".format(post_id))
                if confirm_nonce == stored_nonce:
                    for key in g.db.keys(KEY_BASE+"post:{0}:*".format(post_id)):
                        g.db.delete(key)
                    g.db.lrem(KEY_BASE+"posts", post_id, 0)
                    return redirect(url_for("show_posts"))
                elif stored_nonce is not None:
                    return "Delete request contained invalid confirmation code."
                else:
                    return "Delete request expired."
            else:
                confirm_nonce = build_nonce()
                g.db.setex(KEY_BASE+"post:{0}:delete_nonce".format(post_id), confirm_nonce, 60)
                return render_template("page_post_delete.html", is_page=False, item_title=g.db.get(KEY_BASE+"post:{0}:title".format(post_id)),
                        action_name="Delete post", action_url=url_for("delete_post", post_id=post_id),
                        site_name=g.site_name, navigation=g.nav, confirm_nonce=confirm_nonce)
        else:
            abort(404)
    else:
        abort(403)

@app.route("/post/<int:post_id>/comment", methods=['POST'])
def post_comment(post_id):
    if g.logged_in:
        new_comment_id = g.db.incr(KEY_BASE+"post:{0}:comment:next_id".format(post_id))
        g.db.set(KEY_BASE+"post:{0}:comment:{1}:author".format(post_id, new_comment_id), g.username)
        g.db.set(KEY_BASE+"post:{0}:comment:{1}:text".format(post_id, new_comment_id), request.form["comment"])
        g.db.set(KEY_BASE+"post:{0}:comment:{1}:timestamp".format(post_id, new_comment_id), datetime.utcnow().strftime(TIME_FMT))
        g.db.rpush(KEY_BASE+"post:{0}:comments".format(post_id), new_comment_id)
        return redirect(url_for("show_post", post_id=post_id)+"#comment-{0}".format(new_comment_id))
    else:
        abort(403)

@app.route("/post/<int:post_id>")
def show_post(post_id):
    title = g.db.get(KEY_BASE+"post:{0}:title".format(post_id))
    if title is not None:
        comments = []
        for comment_id in g.db.lrange(KEY_BASE+"post:{0}:comments".format(post_id), 0, -1):
            comments.append({
                "author": g.db.get(KEY_BASE+"post:{0}:comment:{1}:author".format(post_id, comment_id)),
                "text": format_comment(g.db.get(KEY_BASE+"post:{0}:comment:{1}:text".format(post_id, comment_id))),
                "timestamp": g.db.get(KEY_BASE+"post:{0}:comment:{1}:timestamp".format(post_id, comment_id)),
                "fancytime": datetime.strptime(g.db.get(KEY_BASE+"post:{0}:comment:{1}:timestamp".format(post_id, comment_id)), TIME_FMT).strftime(FANCY_TIME_FMT),
                "id": comment_id
                })
        return render_template("posts.html", title=title,
                posts=[{
                    "title": title,
                    "body": g.md.convert(g.db.get(KEY_BASE+"post:{0}:body".format(post_id))),
                    "author": g.db.get(KEY_BASE+"post:{0}:author".format(post_id)),
                    "timestamp": g.db.get(KEY_BASE+"post:{0}:timestamp".format(post_id)),
                    "fancytime": datetime.strptime(g.db.get(KEY_BASE+"post:{0}:timestamp".format(post_id)), TIME_FMT).strftime(FANCY_TIME_FMT),
                    "id": post_id,
                    "comments": comments,
                    "num_comments": len(comments),
                    }],
                site_name=g.site_name, sidebar_sections=[], navigation=g.nav,
                username=g.username, user_is_admin=g.user_is_admin, multi_post=False)
    else:
        if post_id < int(g.db.get(KEY_BASE+"post:next_id")):
            return "This post was deleted."
        abort(404)


### PAGES

@app.route("/page/new", methods=['GET', 'POST'])
def new_page():
    if g.user_is_admin:
        if request.method == "POST":
            new_page_slug = request.form["slug"].lower().strip()
            if new_page_slug in ["new", "delete", "edit", ""]:
                return "Invalid page slug."
            elif not g.db.sismember(KEY_BASE+"pages", new_page_slug):
                g.db.set(KEY_BASE+"page:{0}:title".format(new_page_slug), request.form["title"])
                g.db.set(KEY_BASE+"page:{0}:body".format(new_page_slug), request.form["body"])
                g.db.sadd(KEY_BASE+"pages", new_page_slug)
                return redirect(url_for("show_page", page_slug=new_page_slug))
            else:
                return "Page slug already in use."
        else:
            return render_template("page_post_edit.html",
                    action_name="Create page", action_url=url_for("new_page"),
                    site_name=g.site_name, navigation=g.nav, is_page=True)
    else:
        abort(403)

@app.route("/page/<page_slug>/edit", methods=['GET', 'POST'])
def edit_page(page_slug):
    if g.user_is_admin:
        if g.db.get(KEY_BASE+"page:{0}:title".format(page_slug)) is not None:
            if request.method == "POST":
                if request.form["slug"].lower() != page_slug.lower():
                    g.db.delete(KEY_BASE+"page:{0}:title".format(page_slug))
                    g.db.delete(KEY_BASE+"page:{0}:body".format(page_slug))
                    g.db.srem(KEY_BASE+"pages", page_slug)
                    page_slug = request.form["slug"]
                    g.db.sadd(KEY_BASE+"pages", page_slug)
                g.db.set(KEY_BASE+"page:{0}:title".format(page_slug), request.form["title"])
                g.db.set(KEY_BASE+"page:{0}:body".format(page_slug), request.form["body"])
                return redirect(url_for("show_page", page_slug=page_slug))
            else:
                return render_template("page_post_edit.html",
                        action_name="Edit page", action_url=url_for("edit_page", page_slug=page_slug),
                        site_name=g.site_name, navigation=g.nav, is_page=True,
                        preset_title=g.db.get(KEY_BASE+"page:{0}:title".format(page_slug)),
                        preset_slug=page_slug,
                        preset_body=g.db.get(KEY_BASE+"page:{0}:body".format(page_slug)))
        else:
            abort(404)
    else:
        abort(403)

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
                    return "Delete request contained invalid confirmation code."
                else:
                    return "Delete request expired."
            else:
                confirm_nonce = build_nonce()
                g.db.setex(KEY_BASE+"page:{0}:delete_nonce".format(page_slug), confirm_nonce, 60)
                return render_template("page_post_delete.html", is_page=True,
                        action_name="Delete page", action_url=url_for("delete_page", page_slug=page_slug),
                        site_name=g.site_name, navigation=g.nav, confirm_nonce=confirm_nonce)
        else:
            abort(404)
    else:
        abort(403)

@app.route("/page/<page_slug>")
def show_page(page_slug):
    title = g.db.get(KEY_BASE+"page:{0}:title".format(page_slug))
    if title is not None:
        return render_template("page.html", title=title,
                page={
                    "title": title,
                    "body": g.md.convert(g.db.get(KEY_BASE+"page:{0}:body".format(page_slug))),
                    "slug": page_slug
                    },
                site_name=g.site_name, sidebar_sections=[], navigation=g.nav,
                username=g.username, user_is_admin=g.user_is_admin)
    else:
        return render_template("full_page.html", title="Page not found",
                page={
                    "title": "Error",
                    "body": g.md.convert("No such page exists. Sorry 'bout that.")
                    },
                site_name=g.site_name, navigation=g.nav), 404


### AUTH

@app.route("/login", methods=["GET", "POST"])
def login():
    if not g.logged_in:
        if request.method == "POST":
            hashed_stored_pw = g.db.get(KEY_BASE+"users:{0}:hashed_pw".format(request.form["username"].lower()))
            if hashed_stored_pw is not None:
                hashed_request_pw = md5(md5(request.form["password"]).hexdigest()).hexdigest()
                if hashed_stored_pw == hashed_request_pw:
                    session["username"] = request.form["username"].lower()
                    return redirect(url_for("show_posts"))
                else:
                    return render_template("login_register.html",
                            action_name="Login", action_url=url_for("login"),
                            site_name=g.site_name, navigation=g.nav,
                            preset_username=request.form["username"],
                            error="Incorrect password.")
            else:
                return render_template("login_register.html",
                        action_name="Login", action_url=url_for("login"),
                        site_name=g.site_name, navigation=g.nav,
                        error="No such user.")
        else:
            return render_template("login_register.html",
                    action_name="Login", action_url=url_for("login"),
                    site_name=g.site_name, navigation=g.nav)
    else:
        return "You're already logged in, numb-nuts!"

@app.route("/logout")
def logout():
    if g.logged_in:
        del session["username"]
        return redirect("/")
    else:
        return "You're not logged in."


### USERS

@app.route("/user/new", methods=['GET', 'POST'])
def new_user():
    if request.method == "POST":
        username = request.form["username"].strip().lower()
        if username in ["new", "delete", ""]:  #reserved words, cannot be usernames; empty name also
            return render_template("login_register.html",
                    action_name="Register", action_url=url_for("new_user"),
                    site_name=g.site_name, navigation=g.nav,
                    error="That username is invalid.")
        elif not g.db.sismember(KEY_BASE+"users", username):
            password = request.form["password"].strip().lower()
            if len(password) > 0:
                g.db.sadd(KEY_BASE+"users", username)
                g.db.set(KEY_BASE+"users:{0}:hashed_pw".format(username),
                        md5(md5(request.form["password"]).hexdigest()).hexdigest())
                if "username" in session:
                    return render_template("full_page.html", title="Success",
                            page={
                                "title": "Success!",
                                "body": g.md.convert("Created user *{0}*.".format(username))
                            },
                            site_name=g.site_name, navigation=g.nav)
                else:
                    session["username"] = username
                    return redirect("/")
            else:
                return render_template("login_register.html",
                        action_name="Register", action_url=url_for("new_user"),
                        site_name=g.site_name, navigation=g.nav,
                        preset_username=username,
                        error="Password cannot be blank.")
        else:
            return render_template("login_register.html",
                    action_name="Register", action_url=url_for("new_user"),
                    site_name=g.site_name, navigation=g.nav,
                    error="That username is already taken.")
    else:
        return render_template("login_register.html",
                action_name="Register", action_url=url_for("new_user"),
                site_name=g.site_name, navigation=g.nav)

if __name__ == "__main__":
    app.secret_key = ",j\x16!|5@\x8a\xe6&tLt\xd3\xd7\x00s\xaa[|\x89\xee\xe7-"  # required for session use
    app.debug = True
    app.run()
