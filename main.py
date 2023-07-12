from functools import wraps

from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm
from flask_gravatar import Gravatar

from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

##CONFIGURE TABLES

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # author = db.Column(db.String(250), nullable=False)

    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    #***************Parent Relationship************* blog_posts >>> comments  #
    comments = relationship("Comment", back_populates="parent_post")

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)

    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")

    # ***************Child Relationship*************  blog_posts >>> comments #
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")


# with app.app_context():
#     db.create_all()


login_manager = LoginManager(app)
# login_manager = LoginManager()
# login_manager.init_app(app)


#Create admin-only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kargs):
        # If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(304)
        # Otherwise continue with the route function
        return f(*args, **kargs)
    return decorated_function



@login_manager.user_loader
def load_user(user_id):
    # return User.query.get(int(user_id))
    return db.session.get(User, user_id)


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    # print(f"curent user auth {current_user.is_authenticated}")
    return render_template("index.html", all_posts=posts)





@app.route('/register', methods=["GET", "POST"])
def register():
    login_form = RegisterForm()
    if login_form.validate_on_submit():
        email = login_form.email.data
        ecount = db.session.query(User).filter_by(email=email).count()
        if ecount>0:
            flash("Email already exist.")
        else:
            name = login_form.name.data
            hpsw = generate_password_hash(login_form.password.data, method='pbkdf2:sha256', salt_length=8)
            new_user = User(name=name, email=email, password=hpsw)
            db.session.add(new_user)
            db.session.commit()

            u = db.session.query(User).filter_by(email=email).first()
            login_user(u)

            return redirect(url_for('get_all_posts'))

    return render_template("register.html", form=login_form)


@app.route('/login', methods=["GET", "POST"])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        # validare existenta elmail
        email = login_form.email.data
        password = login_form.password.data
        # print(f"Email cautat {email}")
        # print(f"Parola introdusa {password}")
        # u = User.query.filter_by(email=email).first()
        u = db.session.query(User).filter_by(email=email).first()
        # print(type(u))
        # print(u.name)
        if u is None:
            # print("NO USER")
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        else:
            # verifica parola
            # print(f"Parola introdusa {password}")
            if check_password_hash(u.password, password=password):
                login_user(u)
                return redirect(url_for('get_all_posts'))
                # return render_template("secrets.html", name=user.name)
            else:
                flash('Password incorrect, please try again.')
                return redirect(url_for('login'))
    return render_template("login.html", form=login_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    comment_form = CommentForm(
        # body=post.body
        body=""
    )
    requested_post = BlogPost.query.get(post_id)
    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need toalogin or register to comment.")
            redirect(url_for("login"))

        new_comment = Comment(
            text = comment_form.body.data,
            comment_author=current_user,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()

    return render_template("post.html", post=requested_post, form=comment_form)


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
            author_id=current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
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


@app.route("/delete/<int:post_id>", methods=["POST"])
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/comment/<int:post_id>", methods=["GET","POST"])
def comment_post(post_id):
    post = db.session.query(BlogPost).get(post_id)
    comment_form = CommentForm(
        # body=post.body
        body = ""
    )
    if comment_form.validate_on_submit():
        return redirect(url_for('get_all_posts'))

    return render_template("comment.html", form=comment_form, post=post)


if __name__ == "__main__":
    # app.run(host='0.0.0.0', port=5000, debug=True)
    app.run(debug=True)
