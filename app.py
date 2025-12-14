import os
from datetime import datetime
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_sqlalchemy import SQLAlchemy
from passlib.hash import bcrypt

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, "market.db")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-key")
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DATABASE_PATH}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"


class Role(db.Model):
    __tablename__ = "roles"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    can_delete_any_listing = db.Column(db.Boolean, default=False)
    can_manage_roles = db.Column(db.Boolean, default=False)
    can_manage_users = db.Column(db.Boolean, default=False)

    def __repr__(self) -> str:
        return f"<Role {self.name}>"


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    discord = db.Column(db.String(120), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey("roles.id"), nullable=False)
    role = db.relationship(Role)
    listings = db.relationship("Listing", back_populates="owner", cascade="all, delete")

    def set_password(self, password: str) -> None:
        self.password_hash = bcrypt.hash(password)

    def check_password(self, password: str) -> bool:
        return bcrypt.verify(password, self.password_hash)


class Listing(db.Model):
    __tablename__ = "listings"
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(50), nullable=False)
    title = db.Column(db.String(120), nullable=False)
    price = db.Column(db.Float, nullable=True)
    description = db.Column(db.Text, nullable=False)
    contact_discord = db.Column(db.String(120), nullable=False)
    image_url = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    owner = db.relationship(User, back_populates="listings")


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def ensure_default_roles():
    """Create baseline roles if database is empty."""
    default_roles = [
        {"name": "Member", "can_delete_any_listing": False, "can_manage_roles": False, "can_manage_users": False},
        {"name": "Moderator", "can_delete_any_listing": True, "can_manage_roles": False, "can_manage_users": False},
        {"name": "Admin", "can_delete_any_listing": True, "can_manage_roles": True, "can_manage_users": True},
    ]
    for role_data in default_roles:
        role = Role.query.filter_by(name=role_data["name"]).first()
        if not role:
            role = Role(**role_data)
            db.session.add(role)
    db.session.commit()


@app.before_request
def init_database():
    """Ensure database exists and contains base roles."""
    if not os.path.exists(DATABASE_PATH):
        db.create_all()
        ensure_default_roles()
    else:
        # The file exists, but roles might be missing if database was reset.
        if not Role.query.first():
            db.create_all()
            ensure_default_roles()


@app.context_processor
def inject_roles():
    return {"current_role": getattr(current_user, "role", None)}


def role_required(permission_check):
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if not permission_check(current_user.role):
                flash("У вас недостатньо прав для цієї дії.", "danger")
                return redirect(url_for("index"))
            return view_func(*args, **kwargs)

        return wrapper

    return decorator


@app.route("/")
def index():
    category = request.args.get("category")
    sort = request.args.get("sort", "date_desc")

    listings_query = Listing.query
    if category and category != "all":
        listings_query = listings_query.filter_by(category=category)

    if sort == "price_asc":
        listings_query = listings_query.order_by(Listing.price.asc())
    elif sort == "price_desc":
        listings_query = listings_query.order_by(Listing.price.desc())
    else:
        listings_query = listings_query.order_by(Listing.created_at.desc())

    listings = listings_query.all()
    categories = ["transport", "real_estate", "clothing", "accessories", "other"]
    return render_template("index.html", listings=listings, categories=categories)


@app.route("/register", methods=["GET", "POST"])
def register():
    ensure_default_roles()
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        discord = request.form.get("discord")

        if not username or not password or not discord:
            flash("Усі поля є обов'язковими.", "danger")
            return redirect(url_for("register"))

        if User.query.filter_by(username=username).first():
            flash("Користувач з таким логіном вже існує.", "danger")
            return redirect(url_for("register"))

        member_role = Role.query.filter_by(name="Member").first()
        user = User(username=username, discord=discord, role=member_role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash("Реєстрація успішна. Увійдіть у систему.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash("Вітаємо, ви увійшли!", "success")
            return redirect(url_for("index"))
        flash("Невірні облікові дані.", "danger")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Ви вийшли з акаунту.", "info")
    return redirect(url_for("index"))


@app.route("/profile")
@login_required
def profile():
    user_listings = Listing.query.filter_by(owner_id=current_user.id).order_by(Listing.created_at.desc()).all()
    return render_template("profile.html", user=current_user, listings=user_listings)


@app.route("/listings/new", methods=["GET", "POST"])
@login_required
def create_listing():
    if request.method == "POST":
        category = request.form.get("category")
        title = request.form.get("title")
        price = request.form.get("price")
        description = request.form.get("description")
        contact_discord = request.form.get("contact_discord")
        image_url = request.form.get("image_url") or None

        if not all([category, title, description, contact_discord]):
            flash("Будь ласка, заповніть усі обов'язкові поля.", "danger")
            return redirect(url_for("create_listing"))

        listing = Listing(
            category=category,
            title=title,
            price=float(price) if price else None,
            description=description,
            contact_discord=contact_discord,
            image_url=image_url,
            owner=current_user,
        )
        db.session.add(listing)
        db.session.commit()
        flash("Оголошення опубліковано!", "success")
        return redirect(url_for("index"))

    categories = ["transport", "real_estate", "clothing", "accessories", "other"]
    return render_template("listing_form.html", categories=categories, listing=None)


@app.route("/listings/<int:listing_id>/edit", methods=["GET", "POST"])
@login_required
def edit_listing(listing_id):
    listing = Listing.query.get_or_404(listing_id)
    if listing.owner_id != current_user.id and not current_user.role.can_delete_any_listing:
        flash("Ви можете редагувати лише свої оголошення.", "danger")
        return redirect(url_for("profile"))

    if request.method == "POST":
        listing.category = request.form.get("category")
        listing.title = request.form.get("title")
        price = request.form.get("price")
        listing.price = float(price) if price else None
        listing.description = request.form.get("description")
        listing.contact_discord = request.form.get("contact_discord")
        listing.image_url = request.form.get("image_url") or None
        db.session.commit()
        flash("Оголошення оновлено.", "success")
        return redirect(url_for("profile"))

    categories = ["transport", "real_estate", "clothing", "accessories", "other"]
    return render_template("listing_form.html", categories=categories, listing=listing)


@app.route("/listings/<int:listing_id>/delete", methods=["POST"])
@login_required
def delete_listing(listing_id):
    listing = Listing.query.get_or_404(listing_id)
    if listing.owner_id != current_user.id and not current_user.role.can_delete_any_listing:
        flash("Ви можете видаляти лише свої оголошення.", "danger")
        return redirect(url_for("profile"))

    db.session.delete(listing)
    db.session.commit()
    flash("Оголошення видалено.", "info")
    return redirect(request.referrer or url_for("index"))


@app.route("/admin")
@login_required
@role_required(lambda role: role.can_manage_users or role.can_manage_roles)
def admin_dashboard():
    listings = Listing.query.order_by(Listing.created_at.desc()).all()
    users = User.query.order_by(User.username).all()
    roles = Role.query.order_by(Role.id).all()
    return render_template("admin_dashboard.html", listings=listings, users=users, roles=roles)


@app.route("/admin/listings/<int:listing_id>/delete", methods=["POST"])
@login_required
@role_required(lambda role: role.can_delete_any_listing)
def admin_delete_listing(listing_id):
    listing = Listing.query.get_or_404(listing_id)
    db.session.delete(listing)
    db.session.commit()
    flash("Оголошення видалено модератором/адміністратором.", "info")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/roles", methods=["GET", "POST"])
@login_required
@role_required(lambda role: role.can_manage_roles)
def manage_roles():
    if request.method == "POST":
        name = request.form.get("name")
        delete_any = bool(request.form.get("can_delete_any_listing"))
        manage_roles_flag = bool(request.form.get("can_manage_roles"))
        manage_users_flag = bool(request.form.get("can_manage_users"))

        if not name:
            flash("Назва ролі обов'язкова.", "danger")
        elif Role.query.filter_by(name=name).first():
            flash("Така роль вже існує.", "danger")
        else:
            role = Role(
                name=name,
                can_delete_any_listing=delete_any,
                can_manage_roles=manage_roles_flag,
                can_manage_users=manage_users_flag,
            )
            db.session.add(role)
            db.session.commit()
            flash("Роль створена.", "success")
            return redirect(url_for("manage_roles"))

    roles = Role.query.order_by(Role.id).all()
    return render_template("admin_roles.html", roles=roles)


@app.route("/admin/roles/<int:role_id>/edit", methods=["GET", "POST"])
@login_required
@role_required(lambda role: role.can_manage_roles)
def edit_role(role_id):
    role = Role.query.get_or_404(role_id)
    if request.method == "POST":
        role.name = request.form.get("name")
        role.can_delete_any_listing = bool(request.form.get("can_delete_any_listing"))
        role.can_manage_roles = bool(request.form.get("can_manage_roles"))
        role.can_manage_users = bool(request.form.get("can_manage_users"))
        db.session.commit()
        flash("Роль оновлена.", "success")
        return redirect(url_for("manage_roles"))
    return render_template("admin_roles_edit.html", role=role)


@app.route("/admin/users/<int:user_id>/role", methods=["POST"])
@login_required
@role_required(lambda role: role.can_manage_users)
def update_user_role(user_id):
    user = User.query.get_or_404(user_id)
    new_role_id = request.form.get("role_id")
    role = Role.query.get(new_role_id)
    if role:
        user.role = role
        db.session.commit()
        flash("Роль користувача оновлена.", "success")
    else:
        flash("Обрана роль не існує.", "danger")
    return redirect(url_for("admin_dashboard"))


@app.errorhandler(404)
def not_found(error):
    return render_template("404.html"), 404


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        ensure_default_roles()
    app.run(host="0.0.0.0", port=5000, debug=True)
