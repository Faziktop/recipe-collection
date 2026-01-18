from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'emil-loh'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///recipes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# Модели базы данных
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    recipes = db.relationship('Recipe', backref='author', lazy=True)


class Recipe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    cuisine = db.Column(db.String(100), nullable=False)
    prep_time = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    ingredients = db.Column(db.Text, nullable=False)
    instructions = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Создаем базу данных и добавляем админа по умолчанию
def create_admin_user():
    with app.app_context():
        db.create_all()
        # Проверяем, существует ли админ
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            hashed_password = generate_password_hash('admin123')
            admin = User(
                username='admin',
                email='admin@recipeapp.com',
                password_hash=hashed_password,
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
            print("Админ создан: username='admin', password='admin123'")


create_admin_user()


# Декоратор для проверки админских прав
def admin_required(f):
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)

    decorated_function.__name__ = f.__name__
    return decorated_function


# Маршруты
@app.route('/')
def index():
    recipes = Recipe.query.order_by(Recipe.created_at.desc()).all()
    return render_template('index.html', recipes=recipes)


@app.route('/recipe/<int:recipe_id>')
def recipe_detail(recipe_id):
    recipe = Recipe.query.get_or_404(recipe_id)
    ingredients_list = recipe.ingredients.split('\n')
    return render_template('recipe_detail.html', recipe=recipe, ingredients_list=ingredients_list)


@app.route('/add_recipe', methods=['GET', 'POST'])
@login_required
def add_recipe():
    if request.method == 'POST':
        title = request.form['title']
        cuisine = request.form['cuisine']
        prep_time = request.form['prep_time']
        description = request.form['description']
        ingredients = request.form['ingredients']
        instructions = request.form['instructions']

        recipe = Recipe(
            title=title,
            cuisine=cuisine,
            prep_time=prep_time,
            description=description,
            ingredients=ingredients,
            instructions=instructions,
            user_id=current_user.id
        )

        db.session.add(recipe)
        db.session.commit()
        flash('Рецепт успешно добавлен!', 'success')
        return redirect(url_for('index'))

    return render_template('add_recipe.html')


@app.route('/recipe/<int:recipe_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_recipe(recipe_id):
    recipe = Recipe.query.get_or_404(recipe_id)

    # Проверка прав: автор или админ
    if recipe.user_id != current_user.id and not current_user.is_admin:
        abort(403)

    if request.method == 'POST':
        recipe.title = request.form['title']
        recipe.cuisine = request.form['cuisine']
        recipe.prep_time = request.form['prep_time']
        recipe.description = request.form['description']
        recipe.ingredients = request.form['ingredients']
        recipe.instructions = request.form['instructions']
        recipe.updated_at = datetime.utcnow()

        db.session.commit()
        flash('Рецепт успешно обновлен!', 'success')
        return redirect(url_for('recipe_detail', recipe_id=recipe.id))

    return render_template('edit_recipe.html', recipe=recipe)


@app.route('/recipe/<int:recipe_id>/delete', methods=['POST'])
@login_required
def delete_recipe(recipe_id):
    recipe = Recipe.query.get_or_404(recipe_id)

    # Проверка прав: автор или админ
    if recipe.user_id != current_user.id and not current_user.is_admin:
        abort(403)

    db.session.delete(recipe)
    db.session.commit()
    flash('Рецепт успешно удален!', 'success')
    return redirect(url_for('my_recipes'))


@app.route('/admin/recipes')
@login_required
@admin_required
def admin_all_recipes():
    recipes = Recipe.query.order_by(Recipe.created_at.desc()).all()
    return render_template('admin_recipes.html', recipes=recipes)


@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin_users.html', users=users)


@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_user(user_id):
    if user_id == current_user.id:
        flash('Вы не можете удалить свой аккаунт!', 'error')
        return redirect(url_for('admin_users'))

    user = User.query.get_or_404(user_id)

    # Удаляем все рецепты пользователя
    Recipe.query.filter_by(user_id=user_id).delete()

    # Удаляем пользователя
    db.session.delete(user)
    db.session.commit()

    flash(f'Пользователь {user.username} и все его рецепты удалены!', 'success')
    return redirect(url_for('admin_users'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Пароли не совпадают!', 'error')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Пользователь с таким именем уже существует', 'error')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Пользователь с таким email уже существует', 'error')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        user = User(username=username, email=email, password_hash=hashed_password)

        db.session.add(user)
        db.session.commit()

        flash('Регистрация прошла успешно! Теперь вы можете войти.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash('Вы успешно вошли в систему!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Неверное имя пользователя или пароль', 'error')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('index'))


@app.route('/my_recipes')
@login_required
def my_recipes():
    recipes = Recipe.query.filter_by(user_id=current_user.id).order_by(Recipe.created_at.desc()).all()
    return render_template('index.html', recipes=recipes, my_recipes=True)


if __name__ == '__main__':
    app.run(debug=False)