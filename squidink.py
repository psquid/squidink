#!/usr/bin/env python
from flask import Flask, redirect, url_for, session, escape, request, render_template, g, abort
from redis import Redis
from hashlib import md5
from markdown import Markdown
from datetime import datetime
import random
app = Flask(__name__)


## UTILITY FUNCTIONS/VARS

TIME_FMT = "%Y-%m-%dT%H:%M:%SZ"
FANCY_TIME_FMT = "%H:%M on %a %b %d %Y (UTC)"
NONCE_CHARS = [chr(c) for c in xrange(ord("A"), ord("Z")+1)]
NONCE_CHARS.extend([chr(c) for c in xrange(ord("a"), ord("z")+1)])
NONCE_CHARS.extend([chr(c) for c in xrange(ord("0"), ord("9")+1)])

@app.before_request
def prepare_globals():
    g.db = Redis()
    g.md = Markdown(safe_mode=True)
    g.site_name = g.db.get("sitename") or "Unnamed SquidInk app"
    if "username" in session:
        g.username = session["username"]
        g.logged_in = True
    else:
        g.username = ""
        g.logged_in = False
    g.nav = [
        {"text": "Home", "href": "/"},
        ]
    for page_slug in list(g.db.smembers("pages")):
        g.nav.append({
            "text": g.db.get("page:{0}:title".format(page_slug)),
            "href": url_for("show_page", page_slug=page_slug)
            })
    if g.db.sismember("admins", g.username):
        g.user_is_admin = True
        g.nav.extend([
            {"text": "New post", "href": "/post/new"},
            {"text": "New page", "href": "/page/new"},
            ])
    else:
        g.user_is_admin = False

@app.route("/favicon.ico")
def redirect_favicon():
    return redirect(url_for('static', filename="favicon.ico"))

def build_nonce(nonce_length=32):
    nonce = ""
    for index in xrange(nonce_length):
        nonce += random.choice(NONCE_CHARS)
    return nonce

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

    if page_num * posts_per_page < g.db.llen("posts"):
        nav_older = url_for("show_posts", page_num=page_num+1, **persist_args)
    else:
        nav_older = None

    post_ids = [int(id) for id in g.db.lrange("posts", 0+(posts_per_page*(page_num-1)), (posts_per_page-1)+(posts_per_page*(page_num-1)))]
    posts = []
    for id in post_ids:
        posts.append({
            "title": g.db.get("post:{0}:title".format(id)),
            "body": g.md.convert(g.db.get("post:{0}:body".format(id))),
            "author": g.db.get("post:{0}:author".format(id)),
            "timestamp": g.db.get("post:{0}:timestamp".format(id)),
            "fancytime": datetime.strptime(g.db.get("post:{0}:timestamp".format(id)), TIME_FMT).strftime(FANCY_TIME_FMT),
            "link": url_for("show_post", post_id=id),
            "id": id,
            })

    return render_template("posts.html", title="", posts=posts,
            nav_newer=nav_newer, nav_older=nav_older,
            site_name=g.site_name, sidebar_sections=[], navigation=g.nav,
            username=g.username, user_is_admin=g.user_is_admin)

@app.route("/post/new", methods=['GET', 'POST'])
def new_post():
    if g.user_is_admin:
        if request.method == "POST":
            new_post_id = g.db.incr("post:next_id")
            g.db.set("post:{0}:title".format(new_post_id), request.form["title"])
            g.db.set("post:{0}:body".format(new_post_id), request.form["body"])
            g.db.set("post:{0}:author".format(new_post_id), session["username"])
            g.db.set("post:{0}:timestamp".format(new_post_id), datetime.utcnow().strftime(TIME_FMT))
            g.db.lpush("posts", new_post_id)
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
        if g.db.get("post:{0}:title".format(post_id)) is not None:
            if request.method == "POST":
                g.db.set("post:{0}:title".format(post_id), request.form["title"])
                g.db.set("post:{0}:body".format(post_id), request.form["body"])
                g.db.set("post:{0}:edit_timestamp".format(post_id), datetime.utcnow().strftime(TIME_FMT))
                return redirect(url_for("show_post", post_id=post_id))
            else:
                return render_template("page_post_edit.html",
                        action_name="Edit post", action_url=url_for("edit_post", post_id=post_id),
                        site_name=g.site_name, navigation=g.nav, is_page=False,
                        preset_title=g.db.get("post:{0}:title".format(post_id)),
                        preset_body=g.db.get("post:{0}:body".format(post_id)))
        else:
            abort(404)
    else:
        abort(403)

@app.route("/post/<int:post_id>/delete", methods=['GET', 'POST'])
def delete_post(post_id):
    if g.user_is_admin:
        if g.db.get("post:{0}:title".format(post_id)) is not None:
            if request.method == "POST":
                confirm_nonce = request.form["confirm_nonce"]
                stored_nonce = g.db.get("post:{0}:delete_nonce".format(post_id))
                if confirm_nonce == stored_nonce:
                    for key in g.db.keys("post:{0}:*".format(post_id)):
                        g.db.delete(key)
                    g.db.lrem("posts", post_id, 0)
                    return redirect(url_for("show_posts"))
                elif stored_nonce is not None:
                    return "Delete request contained invalid confirmation code."
                else:
                    return "Delete request expired."
            else:
                confirm_nonce = build_nonce()
                g.db.setex("post:{0}:delete_nonce".format(post_id), confirm_nonce, 60)
                return render_template("page_post_delete.html", is_page=False, item_title=g.db.get("post:{0}:title".format(post_id)),
                        action_name="Delete post", action_url=url_for("delete_post", post_id=post_id),
                        site_name=g.site_name, navigation=g.nav, confirm_nonce=confirm_nonce)
        else:
            abort(404)
    else:
        abort(403)

@app.route("/post/<int:post_id>")
def show_post(post_id):
    title = g.db.get("post:{0}:title".format(post_id))
    if title is not None:
        return render_template("posts.html", title=title,
                posts=[{
                    "title": title,
                    "body": g.md.convert(g.db.get("post:{0}:body".format(post_id))),
                    "author": g.db.get("post:{0}:author".format(post_id)),
                    "timestamp": g.db.get("post:{0}:timestamp".format(post_id)),
                    "fancytime": datetime.strptime(g.db.get("post:{0}:timestamp".format(post_id)), TIME_FMT).strftime(FANCY_TIME_FMT),
                    "id": post_id
                    }],
                site_name=g.site_name, sidebar_sections=[], navigation=g.nav,
                username=g.username, user_is_admin=g.user_is_admin)
    else:
        if post_id < int(g.db.get("post:next_id")):
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
            elif not g.db.sismember("pages", new_page_slug):
                g.db.set("page:{0}:title".format(new_page_slug), request.form["title"])
                g.db.set("page:{0}:body".format(new_page_slug), request.form["body"])
                g.db.sadd("pages", new_page_slug)
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
        if g.db.get("page:{0}:title".format(page_slug)) is not None:
            if request.method == "POST":
                if request.form["slug"].lower() != page_slug.lower():
                    g.db.delete("page:{0}:title".format(page_slug))
                    g.db.delete("page:{0}:body".format(page_slug))
                    g.db.srem("pages", page_slug)
                    page_slug = request.form["slug"]
                    g.db.sadd("pages", page_slug)
                g.db.set("page:{0}:title".format(page_slug), request.form["title"])
                g.db.set("page:{0}:body".format(page_slug), request.form["body"])
                return redirect(url_for("show_page", page_slug=page_slug))
            else:
                return render_template("page_post_edit.html",
                        action_name="Edit page", action_url=url_for("edit_page", page_slug=page_slug),
                        site_name=g.site_name, navigation=g.nav, is_page=True,
                        preset_title=g.db.get("page:{0}:title".format(page_slug)),
                        preset_slug=page_slug,
                        preset_body=g.db.get("page:{0}:body".format(page_slug)))
        else:
            abort(404)
    else:
        abort(403)

@app.route("/page/<page_slug>/delete", methods=['GET', 'POST'])
def delete_page(page_slug):
    if g.user_is_admin:
        if g.db.get("page:{0}:title".format(page_slug)) is not None:
            if request.method == "POST":
                confirm_nonce = request.form["confirm_nonce"]
                stored_nonce = g.db.get("page:{0}:delete_nonce".format(page_slug))
                if confirm_nonce == stored_nonce:
                    for key in g.db.keys("page:{0}:*".format(page_slug)):
                        g.db.delete(key)
                    g.db.srem("pages", page_slug)
                    return redirect(url_for("show_posts"))
                elif stored_nonce is not None:
                    return "Delete request contained invalid confirmation code."
                else:
                    return "Delete request expired."
            else:
                confirm_nonce = build_nonce()
                g.db.setex("page:{0}:delete_nonce".format(page_slug), confirm_nonce, 60)
                return render_template("page_post_delete.html", is_page=True,
                        action_name="Delete page", action_url=url_for("delete_page", page_slug=page_slug),
                        site_name=g.site_name, navigation=g.nav, confirm_nonce=confirm_nonce)
        else:
            abort(404)
    else:
        abort(403)

@app.route("/page/<page_slug>")
def show_page(page_slug):
    title = g.db.get("page:{0}:title".format(page_slug))
    if title is not None:
        return render_template("page.html", title=title,
                page={
                    "title": title,
                    "body": g.md.convert(g.db.get("page:{0}:body".format(page_slug))),
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

@app.route("/login", methods=["POST"])
def login():
    if not g.logged_in:
        hashed_stored_pw = g.db.get('users:{0}:hashed_pw'.format(request.form["username"].lower()))
        if hashed_stored_pw is not None:
            hashed_request_pw = md5(md5(request.form["password"]).hexdigest()).hexdigest()
            if hashed_stored_pw == hashed_request_pw:
                session["username"] = request.form["username"].lower()
                return redirect("/")
            else:
                return "Sorry, bad password."
        else:
            return "No such user."
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
        elif not g.db.sismember("users", username):
            password = request.form["password"].strip().lower()
            if len(password) > 0:
                g.db.sadd("users", username)
                g.db.set("users:{0}:hashed_pw".format(username),
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
    app.run(debug=True)
