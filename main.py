from flask import Flask, render_template, redirect, url_for, flash,request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired

from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user


app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
login_manager = LoginManager()
login_manager.init_app(app)
Bootstrap(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField("Sign Me Up!")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Let Me In!")

class Reset(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password1 = PasswordField("NewPassword", validators=[DataRequired()])
    password2=PasswordField("TypePasswordAgain",validators=[DataRequired()])
    submit = SubmitField("Let Me In!")

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    todo2 = relationship("Todo",back_populates="todo1")


class Todo( db.Model):
    __tablename__ = "todo"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    todo = db.Column(db.String(500))
    todo1=relationship("User", back_populates="todo2")

db.create_all()


@app.route('/')
def home():
    list = Todo.query.all()
    return render_template("index.html",lists=list,current_user=current_user)

@app.route('/add',methods=["POST"])
def add():
    if request.method=="POST":
        print(request.form.get('todo'))
        new_list=Todo(todo=request.form.get('description'))
        db.session.add(new_list)
        db.session.commit()
        return redirect(url_for("home"))

@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():

        if User.query.filter_by(email=form.email.data).first():
            print(User.query.filter_by(email=form.email.data).first())
            #User already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=form.email.data,
            name=form.name.data,
            password=hash_and_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("home"))

    return render_template("register.html", form=form)

@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()
        # Email doesn't exist or password incorrect.
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('home'))
    return render_template("login.html", form=form, )


@app.route('/ResetPassword', methods=["GET", "POST"])
def ResetPassword():
    form = Reset()
    if form.validate_on_submit():
        email = form.email.data
        password1 = form.password1.data
        password2=form.password2.data

        if (password1 == password2):
            hash_and_salted_password = generate_password_hash(
                form.password1.data,
                method='pbkdf2:sha256',
                salt_length=8
            )
            user=User.query.filter_by(email=email).first()
            user.password=hash_and_salted_password
            db.session.commit()
            login_user(user)
            return redirect(url_for("home"))
        else:
            flash('please enter valid Email or Password.')
            return redirect(url_for('ResetPassword'))

    return render_template("ResetPassword.html", form=form, )

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route("/delete/<int:list_id>")

def delete_list(list_id):
    post_to_delete = Todo.query.get(list_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('home'))



if __name__ == "__main__":
    app.run(debug=True)