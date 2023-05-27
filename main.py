from flask import Flask, render_template, redirect, url_for, flash, abort, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, UserRegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
import smtplib
import os
from dotenv import load_dotenv

load_dotenv("/.env")
MY_EMAIL = os.getenv('MY_EMAIL')
MY_EMAIL_PASSWORD = os.getenv('MY_EMAIL_PASSWORD')

app = Flask(__name__)
app.app_context().push()
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
ckeditor = CKEditor(app)
Bootstrap(app)
gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)


##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
        return User.query.get(int(user_id))


##CONFIGURE TABLES

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="commenter")

    def generate_password(self, data):
        self.password = generate_password_hash(data, method='pbkdf2:sha256', salt_length=8)

    def check_password(self, data):
        return check_password_hash(self.password, data)

    @property
    def admin(self):
        if self.id == 1:
            return True


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    # parent = relationship("User", back_populates="children")
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="post")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    commenter_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    post = relationship("BlogPost", back_populates="comments")
    commenter = relationship("User", back_populates="comments")
    text = db.Column(db.Text, nullable=False)


with app.app_context():
    db.create_all()

def admin_only(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if current_user.admin:
            return function(*args, **kwargs)
        else:
            abort(403)
    return wrapper


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['GET', 'POST'])
def register():
    user_register_form = UserRegisterForm()
    if user_register_form.validate_on_submit():
        new_user = User()
        new_user.email = user_register_form.email.data
        new_user.name = user_register_form.name.data
        password = user_register_form.password.data
        if User.query.filter_by(email=new_user.email).first():
            flash(f'User {new_user.email} already exists! Log in instead!', 'info')
            return redirect(url_for('login'))
        new_user.generate_password(password)
        print(new_user.password)
        db.session.add(new_user)
        db.session.commit()
        new_user.id = User.query.filter_by(email=new_user.email).first().id
        login_user(new_user)
        return redirect(url_for('get_all_posts'))

    return render_template("register.html", form=user_register_form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        user = User()
        user.email = login_form.email.data
        password = login_form.password.data
        registered_user = User.query.filter_by(email=user.email).first()
        if registered_user:
            user.id = registered_user.id
            if registered_user.check_password(password):
                login_user(user)
                if current_user.admin:
                    print(current_user.id)
                else:
                    print("not admin")
                return redirect(url_for('get_all_posts'))
            else:
                flash(f'Password incorrect, please try again!', 'warning')
                return render_template("login.html", form=login_form)
        else:
            flash(f"This user(email: {user.email}) doesn't exist, please try again or register!", 'error')
    return render_template("login.html", form=login_form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)

    comment_form = CommentForm()
    if comment_form.validate_on_submit():
        if current_user.is_anonymous:
            flash(f'You need to log in or register to comment!', 'warning')
            return redirect(url_for('login'))
        else:
            new_comment = Comment(
                commenter=current_user,
                post=requested_post,
                text=comment_form.body.data
            )
            db.session.add(new_comment)
            db.session.commit()

    return render_template("post.html", post=requested_post, form=comment_form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact", methods=["POST", "GET"])
def contact():
    if request.method == 'GET':
        h1_message = "Contact Me"
        return render_template("contact.html", h1=h1_message)
    elif request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        message = request.form['message']
        print(f"{name}\n{email}\n{phone}\n{message}")
        h1_message = "Successfully sent your message."

        my_email = MY_EMAIL
        password = MY_EMAIL_PASSWORD

        with smtplib.SMTP("smtp.gmail.com") as connection:
            connection.starttls()
            connection.login(my_email, password)
            connection.sendmail(
                from_addr=my_email,
                to_addrs=my_email,
                msg=f"Subject: Customer Message\n\nName: {name}\n{email}\n{phone}\n{message}"
            )
        return render_template("contact.html", h1=h1_message)


@app.route("/new-post", methods=['GET', 'POST'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            author_id=current_user.id,
            author=User.query.filter_by(id=current_user.id).first(),
            title=form.title.data,
            subtitle=form.subtitle.data,
            date=date.today().strftime("%B %d, %Y"),
            body=form.body.data,
            img_url=form.img_url.data
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
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
    app.run(host='0.0.0.0', port=8000, debug=True)
