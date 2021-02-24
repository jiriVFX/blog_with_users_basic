import os

from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy import Table, Column, Integer, ForeignKey
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LogInForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)

login_manager = LoginManager()
login_manager.init_app(app)

gravatar = Gravatar(app,
                    size=200,
                    rating='pg',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

##CONNECT TO DB
if os.environ.get("DATABASE_URL"):
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    # Author of the blog post
    author_id = db.Column(db.Integer, ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")
    # Comments under the Blog Post
    comments = relationship("Comment", back_populates="parent_post")


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="author")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    # Author of the comment
    author_id = db.Column(db.Integer, ForeignKey("users.id"))
    author = relationship("User", back_populates="comments")
    # Comment's Blog Post
    post_id = db.Column(db.Integer, ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")

db.create_all()

# Load user function must be implemented
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def admin_only(function):
    @wraps(function)
    def wrapper_function(*args, **kwargs):
        if current_user.is_authenticated and current_user.id == 1:
            return function(*args, **kwargs)
        else:
            # User is not authorized to access this route
            return abort(403)
    return wrapper_function


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        email = request.form["email"]
        password = request.form["password"]
        name = request.form["name"]

        if not User.query.filter_by(email=email).first():
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
            new_user = User(email=email, password=hashed_password, name=name)
            db.session.add(new_user)
            db.session.commit()

            # Session login
            login_user(new_user)
            flash("Thanks for your registration.")
            return redirect(url_for("get_all_posts"))
        else:
            flash("Account with the entered Email already exists. Please, log in.")
            return redirect(url_for("login"))
    return render_template("register.html", form=register_form)


@app.route('/login', methods=["GET", "POST"])
def login():
    login_form = LogInForm()
    if login_form.validate_on_submit():
        email = request.form["email"]
        password = request.form["password"]

        this_user = User.query.filter_by(email=email).first()
        if not this_user:
            print("User email does not exist")
            flash("Wrong username or password.")
            return redirect(url_for("login"))

        if check_password_hash(this_user.password, password):
            # Login and validate the user.
            login_user(this_user)
            flash("You were successfully logged in.")
            print("Success!")
            return redirect(url_for("get_all_posts"))
        else:
            flash("Wrong username or password.")
            error = "Invalid credentials"
            print("Wrong password.")
            return render_template("login.html", form=login_form)

    return render_template("login.html", form=login_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comment_form = CommentForm()

    if comment_form.validate_on_submit():
        if current_user.is_authenticated:
            comment_text = request.form["body"]
            new_comment = Comment(text=comment_text, author=current_user, parent_post=requested_post)
            db.session.add(new_comment)
            db.session.commit()
            # Clean the text in the form after posting the comment
            comment_form.body.data = ""
        else:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))

    return render_template("post.html", post=requested_post, form=comment_form, current_user=current_user)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")



@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)



@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)



@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
