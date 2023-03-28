from flask import Flask, redirect, url_for, render_template, flash, request
from flask_bootstrap import Bootstrap
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from wtforms import StringField, PasswordField, SubmitField
from flask_wtf import FlaskForm
from wtforms.validators import DataRequired
from dotenv import load_dotenv
import stripe
import os

load_dotenv("C:\\Users\\sharm\\PycharmProject\\todo-list\\.env")
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
Bootstrap(app)

stripe.api_key = os.environ.get('STRIPE_API_KEY')
YOUR_DOMAIN = 'http://127.0.0.1:5000'

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///data.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


class RegisterForm(FlaskForm):
    name = StringField("User Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign Me Up!")


class LoginUser(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


class Users(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False)
    password = db.Column(db.String, nullable=False)
    sl_item = relationship("SelectedProduct", back_populates="selector")
    bt_item = relationship("BoughtProduct", back_populates="buyer")


class SelectedProduct(UserMixin, db.Model):
    __tablename__ = "selected_product"
    id = db.Column(db.Integer, primary_key=True)
    product_name = db.Column(db.String, nullable=False)
    product_price = db.Column(db.String, nullable=False)
    selector = relationship("Users", back_populates="sl_item")
    selector_id = db.Column(db.Integer, db.ForeignKey("users.id"))


class BoughtProduct(UserMixin, db.Model):
    __tablename__ = "bought_product"
    id = db.Column(db.Integer, primary_key=True)
    product_name = db.Column(db.String, nullable=False)
    product_price = db.Column(db.String, nullable=False)
    buyer = relationship("Users", back_populates="bt_item")
    buyer_id = db.Column(db.Integer, db.ForeignKey("users.id"))


# with app.app_context():
#     db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginUser()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = Users.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash("Invalid credentials")
    return render_template("login.html", form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if Users.query.filter_by(email=form.email.data).first():
            flash("You have already registered. Log in to continue.")
            return redirect(url_for('login'))
        else:
            new_user = Users(
                name=form.name.data,
                email=form.email.data,
                password=generate_password_hash(form.password.data, "pbkdf2:sha256", 8)
            )
        db.session.add(new_user)
        db.session.commit()
        user = Users.query.filter_by(email=form.email.data).first()
        login_user(user)
        return redirect(url_for('home'))
    return render_template("register.html", form=form)


@app.route('/selected')
@login_required
def selected():
    name = request.args.get('name')
    price = request.args.get('price')
    selected_item = SelectedProduct(
        product_name=name,
        product_price=price,
        selector_id=current_user.id
    )
    db.session.add(selected_item)
    db.session.commit()
    count_list = SelectedProduct.query.filter_by(selector_id=current_user.id).all()
    count = count_list[-1]
    return render_template("index.html", count=count)


@app.route('/goto_cart')
def goto_cart():
    items = SelectedProduct.query.filter_by(selector_id=current_user.id).all()
    return render_template('checkout.html', items=items)


@app.route('/success')
def success():
    return render_template('success.html')


@app.route("/cancel")
def cancel():
    return render_template('cancel.html')


@app.route('/create-checkout-session', methods=['POST', "GET"])
def create_checkout_session():
    price = request.args.get('price')
    price = price.split("$")
    price = price[1].split(".")
    price = int(price[0])
    name = request.args.get('name')
    try:
        checkout_session = stripe.checkout.Session.create(
            line_items=[
                {
                    # Provide the exact Price ID (for example, pr_1234) of the product you want to sell
                    'price_data': {
                'currency': 'inr',
                'product_data': {
                    'name': name,
                },
                'unit_amount': price * 78,
            },
                    'quantity': 1,
                },
            ],
            mode='payment',
            success_url=YOUR_DOMAIN + '/success',
            cancel_url=YOUR_DOMAIN + '/cancel',
        )
    except Exception as e:
        return str(e)

    return redirect(checkout_session.url, code=303)


if __name__ == '__main__':
    app.run(debug=True)
