#!/usr/bin/env python
from flask import Flask, redirect, url_for, session, escape, request, abort, render_template
from redis import Redis
from hashlib import md5
from markdown import Markdown
from datetime import datetime
app = Flask(__name__)

site_name = "Squid's Scribblings"
nav_items = [
        {"text": "Home", "href": "/"},
        ]
admin_nav_items = [
        {"text": "New post", "href": "/post/new"},
        {"text": "New page", "href": "/page/new"},
        ]
time_fmt = "%Y-%m-%dT%H:%M:%SZ"
fancy_time_fmt = "%H:%M on %a %b %d %Y (UTC)"

@app.route("/")
@app.route("/page/<int:page_num>")
def show_posts(page_num=1):
    db = Redis()
    md = Markdown(safe_mode="escape")
    nav = nav_items[:]
    for page_slug in list(db.smembers("pages")):
        nav.append({
            "text": db.get("page:{0}:title".format(page_slug)),
            "href": url_for("show_page", page_slug=page_slug)
            })
    if "username" in session:
        username = session["username"]
        if db.sismember("admins", username):
            nav.extend(admin_nav_items)
    else:
        username = ""
    posts_per_page = int(request.args.get("per_page", 10))
    if page_num > 1:
        if "per_page" in request.args:
            nav_newer = url_for("show_posts", page_num=page_num-1, per_page=request.args["per_page"])
        else:
            nav_newer = url_for("show_posts", page_num=page_num-1)
    else:
        nav_newer = None
    if page_num * posts_per_page < db.llen("posts"):
        if "per_page" in request.args:
            nav_older = url_for("show_posts", page_num=page_num+1, per_page=request.args["per_page"])
        else:
            nav_older = url_for("show_posts", page_num=page_num+1)
    else:
        nav_older = None
    post_ids = [int(id) for id in db.lrange("posts", 0+(posts_per_page*(page_num-1)), (posts_per_page-1)+(posts_per_page*(page_num-1)))]
    print post_ids
    posts = []
    for id in post_ids:
        posts.append({
            "title": db.get("post:{0}:title".format(id)),
            "body": md.convert(db.get("post:{0}:body".format(id))),
            "author": db.get("post:{0}:author".format(id)),
            "timestamp": db.get("post:{0}:timestamp".format(id)),
            "fancytime": datetime.strptime(db.get("post:{0}:timestamp".format(id)), time_fmt).strftime(fancy_time_fmt),
            "link": url_for("show_post", post_id=id),
            "id": id,
            })
    return render_template("posts.html", title="", posts=posts,
            site_name=site_name, sidebar_sections=[], navigation=nav,
            username=username, user_is_admin=db.sismember("admins", username),
            nav_newer=nav_newer, nav_older=nav_older)

@app.route("/login", methods=["POST"])
def login():
    if not "username" in session:
        db = Redis()
        hashed_stored_pw = db.get('users:{0}:hashed_pw'.format(request.form["username"].lower()))
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
    if "username" in session:
        del session["username"]
        return redirect("/")
    else:
        return "You're not logged in."

@app.route("/favicon.ico")
def redirect_favicon():
    return redirect(url_for('static', filename="favicon.ico"))

@app.route("/post/new", methods=['GET', 'POST'])
def new_post():
    db = Redis()
    if "username" in session and db.sismember("admins", session["username"]):
        if request.method == "POST":
            new_post_id = db.incr("post:next_id")
            db.set("post:{0}:title".format(new_post_id), request.form["title"])
            db.set("post:{0}:body".format(new_post_id), request.form["body"])
            db.set("post:{0}:author".format(new_post_id), session["username"])
            db.set("post:{0}:timestamp".format(new_post_id), datetime.utcnow().strftime(time_fmt))
            db.lpush("posts", new_post_id)
            return redirect(url_for("show_post", post_id=new_post_id))
        else:
            return """
            <form action="" method="post">
                <p><input type="text" name="title"></p>
                <p><input type="textarea" name="body"></p>
                <p><input type="submit" name="Create post"></p>
            </form>
            """
    else:
        abort(404)

@app.route("/page/new", methods=['GET', 'POST'])
def new_page():
    db = Redis()
    if "username" in session and db.sismember("admins", session["username"]):
        if request.method == "POST":
            new_page_slug = request.form["slug"].lower().strip()
            if new_page_slug in ["new", "delete", "edit", ""]:
                return "Invalid page slug."
            elif not db.sismember("pages", new_page_slug):
                db.set("page:{0}:title".format(new_page_slug), request.form["title"])
                db.set("page:{0}:body".format(new_page_slug), request.form["body"])
                db.sadd("pages", new_page_slug)
                return redirect(url_for("show_page", page_slug=new_page_slug))
            else:
                return "Page slug already in use."
        else:
            return """
            <form action="" method="post">
                <p><input type="text" name="title"></p>
                <p><input type="text" name="slug"></p>
                <p><input type="textarea" name="body"></p>
                <p><input type="submit" name="Create post"></p>
            </form>
            """
    else:
        abort(404)

@app.route("/post/<int:post_id>")
def show_post(post_id):
    db = Redis()
    md = Markdown(safe_mode="escape")
    nav = nav_items[:]
    for page_slug in list(db.smembers("pages")):
        nav.append({
            "text": db.get("page:{0}:title".format(page_slug)),
            "href": url_for("show_page", page_slug=page_slug)
            })
    if "username" in session:
        username = session["username"]
        if db.sismember("admins", username):
            nav.extend(admin_nav_items)
    else:
        username = ""
    title = db.get("post:{0}:title".format(post_id))
    if title is not None:
        return render_template("posts.html", title=title,
                posts=[{
                    "title": title,
                    "body": md.convert(db.get("post:{0}:body".format(post_id))),
                    "author": db.get("post:{0}:author".format(post_id)),
                    "timestamp": db.get("post:{0}:timestamp".format(post_id)),
                    "fancytime": datetime.strptime(db.get("post:{0}:timestamp".format(post_id)), time_fmt).strftime(fancy_time_fmt),
                    "id": post_id
                    }],
                site_name=site_name, sidebar_sections=[], navigation=nav,
                username=username, user_is_admin=db.sismember("admins", username))
    else:
        abort(404)

@app.route("/page/<page_slug>")
def show_page(page_slug):
    db = Redis()
    md = Markdown(safe_mode="escape")
    nav = nav_items[:]
    for slug in list(db.smembers("pages")):
        nav.append({
            "text": db.get("page:{0}:title".format(slug)),
            "href": url_for("show_page", page_slug=slug)
            })
    if "username" in session:
        username = session["username"]
        if db.sismember("admins", username):
            nav.extend(admin_nav_items)
    else:
        username = ""
    title = db.get("page:{0}:title".format(page_slug))
    if title is not None:
        return render_template("page.html", title=title,
                page={
                    "title": title,
                    "body": md.convert(db.get("page:{0}:body".format(page_slug))),
                    "slug": page_slug
                    },
                site_name=site_name, sidebar_sections=[], navigation=nav,
                username=username, user_is_admin=db.sismember("admins", username))
    else:
        return render_template("full_page.html", title="Page not found",
                page={
                    "title": "Error",
                    "body": md.convert("No such page exists. Sorry 'bout that.")
                    },
                site_name=site_name, navigation=nav), 404

@app.route("/user/new", methods=['GET', 'POST'])
def new_user():
    db = Redis()
    md = Markdown(safe_mode=True)
    nav = nav_items[:]
    for page_slug in list(db.smembers("pages")):
        nav.append({
            "text": db.get("page:{0}:title".format(page_slug)),
            "href": url_for("show_page", page_slug=page_slug)
            })
    if "username" in session:
        username = session["username"]
        if db.sismember("admins", username):
            nav.extend(admin_nav_items)
    else:
        username = ""
    if request.method == "POST":
        username = request.form["username"].strip().lower()
        if username in ["new", "delete", ""]:  #reserved words, cannot be usernames; empty name also
            return render_template("login_register.html",
                    action_name="Register", action_url=url_for("new_user"),
                    site_name=site_name, navigation=nav,
                    error="That username is invalid.")
        elif not db.sismember("users", username):
            password = request.form["password"].strip().lower()
            if len(password) > 0:
                db.sadd("users", username)
                db.set("users:{0}:hashed_pw".format(username),
                        md5(md5(request.form["password"]).hexdigest()).hexdigest())
                if "username" in session:
                    return render_template("full_page.html", title="Success",
                            page={
                                "title": "Success!",
                                "body": md.convert("Created user *{0}*.".format(username))
                            },
                            site_name=site_name, navigation=nav)
                else:
                    session["username"] = username
                    return redirect("/")
            else:
                return render_template("login_register.html",
                        action_name="Register", action_url=url_for("new_user"),
                        site_name=site_name, navigation=nav,
                        error="Password cannot be blank.")
        else:
            return render_template("login_register.html",
                    action_name="Register", action_url=url_for("new_user"),
                    site_name=site_name, navigation=nav,
                    error="That username is already taken.")
    else:
        return render_template("login_register.html",
                action_name="Register", action_url=url_for("new_user"),
                site_name=site_name, navigation=nav)

if __name__ == "__main__":
    app.secret_key = ",j\x16!|5@\x8a\xe6&tLt\xd3\xd7\x00s\xaa[|\x89\xee\xe7-"  # required for session use
    app.run(debug=True)
