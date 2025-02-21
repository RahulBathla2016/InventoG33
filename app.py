from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, EmailField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
from datetime import datetime
from email_validator import validate_email, EmailNotValidError
import os


# App Configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-change-this')
# Updated database path to be absolute
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'inventory.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False    

#initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)                                                                                    
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    items = db.relationship('InventoryItem', backref='user', lazy=True, cascade='all, delete-orphan')

    def __repr__(self):
        return f'<User {self.email}>'
    
    def get_name(self):
        return f"{self.first_name} {self.last_name}"

class InventoryItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<InventoryItem {self.name}>'

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'category': self.category,
            'quantity': self.quantity,
            'price': self.price,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }

# Forms
class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(), Length(min=2, max=50)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(min=2, max=50)])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message='Password must be at least 8 characters long')
    ])
    confirm_password = PasswordField('Confirm Password', 
                                    validators=[DataRequired(), EqualTo('password', message='Passwords must match')])
    accept_tos = BooleanField('I accept the Terms of Service and Privacy Policy', validators=[DataRequired()])
    submit = SubmitField('Register')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered. Please use a different email or login.')

class ResetPasswordRequestForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route("/")
def index():
    current_year = datetime.now().year 
    return render_template("index.html", year=current_year)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegistrationForm()
    
    if form.validate_on_submit():
        try:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            new_user = User(
                first_name=form.first_name.data,
                last_name=form.last_name.data,
                email=form.email.data,
                password_hash=hashed_password
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            flash('Your account has been created! You are now logged in.', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating account: {str(e)}', 'danger')
    
    return render_template('register.html', form=form, year=datetime.now().year)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            flash('Login successful!', 'success')
            return redirect(next_page if next_page else url_for('dashboard'))
        else:
            flash('Login unsuccessful. Please check email and password.', 'danger')
    
    return render_template('login.html', form=form, year=datetime.now().year)

@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = ResetPasswordRequestForm()
    
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            flash('Check your email for instructions to reset your password', 'info')
            return redirect(url_for('login'))
        else:
            flash('Email not found in our records', 'warning')
    
    return render_template('reset_password_request.html', form=form, year=datetime.now().year)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', year=datetime.now().year, datetime=datetime)

@app.route('/reports')
@login_required
def reports():
    return render_template('reports.html')

@app.route('/dashboard')
@login_required
def dashboard():
    # try:
        items = InventoryItem.query.filter_by(user_id=current_user.id).all()
        stats = {
            'total_items': len(items),
            'total_value': sum(item.price * item.quantity for item in items),
            'low_stock': sum(1 for item in items if 0 < item.quantity <= 10),
            'out_of_stock': sum(1 for item in items if item.quantity == 0),
            'categories': len(set(item.category for item in items))
        }
        return render_template('dashboard.html', stats=stats, year=datetime.now().year)

@app.route('/inventory')
@login_required
def inventory():
    try:
        items = InventoryItem.query.filter_by(user_id=current_user.id).all()
        return render_template('inventory.html', items=items, year=datetime.now().year)
    except Exception as e:
        flash('Error loading inventory data.', 'danger')
        app.logger.error(f'Inventory error: {str(e)}')
        return redirect(url_for('dashboard'))


@app.route('/api/inventory', methods=['GET', 'POST'])
@login_required
def api_inventory():
    if request.method == 'GET':
        try:
            items = InventoryItem.query.filter_by(user_id=current_user.id).all()
            return jsonify([item.to_dict() for item in items])
        except Exception as e:
            app.logger.error(f'Error fetching inventory: {str(e)}')
            return jsonify({'error': 'Failed to fetch inventory'}), 500

    elif request.method == 'POST':
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400
            
            # Validation
            required_fields = ['name', 'category', 'quantity', 'price']
            if not all(field in data for field in required_fields):
                return jsonify({'error': 'Missing required fields'}), 400

            try:
                quantity = int(data['quantity'])
                if quantity < 0:
                    return jsonify({'error': 'Quantity must be non-negative'}), 400
            except ValueError:
                return jsonify({'error': 'Invalid quantity'}), 400

            try:
                price = float(data['price'])
                if price < 0:
                    return jsonify({'error': 'Price must be non-negative'}), 400
            except ValueError:
                return jsonify({'error': 'Invalid price'}), 400

            new_item = InventoryItem(
                name=data['name'],
                category=data['category'],
                quantity=quantity,
                price=price,
                user_id=current_user.id
            )
            
            db.session.add(new_item)
            db.session.commit()
            
            return jsonify(new_item.to_dict()), 201

        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error creating inventory item: {str(e)}')
            return jsonify({'error': 'Failed to create inventory item'}), 500


@app.route('/api/inventory/<int:item_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def api_inventory_item(item_id):
    item = InventoryItem.query.get_or_404(item_id)
    
    # Check ownership
    if item.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403

    if request.method == 'GET':
        return jsonify(item.to_dict())

    elif request.method == 'PUT':
        try:
            data = request.get_json()
            
            # Validation
            if 'quantity' in data and (not isinstance(data['quantity'], int) or data['quantity'] < 0):
                return jsonify({'error': 'Invalid quantity'}), 400

            if 'price' in data:
                try:
                    price = float(data['price'])
                    if price < 0:
                        raise ValueError
                    data['price'] = price
                except ValueError:
                    return jsonify({'error': 'Invalid price'}), 400

            # Update fields
            for key, value in data.items():
                if hasattr(item, key):
                    setattr(item, key, value)

            db.session.commit()
            return jsonify(item.to_dict())

        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500

    elif request.method == 'DELETE':
        try:
            db.session.delete(item)
            db.session.commit()
            return jsonify({'message': 'Item deleted successfully'})
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500
        

@app.route('/inventory/edit/<int:item_id>', methods=['GET', 'POST'])
@login_required
def edit_inventory_item(item_id):
    
    item = InventoryItem.query.get_or_404(item_id)
    
    # Use the same ownership check as the API route
    if item.user_id != current_user.id:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('inventory'))

    if request.method == 'GET':
        # Display the edit form with current item values
        return render_template('edit.html', product=item, year=datetime.now().year)
    
    elif request.method == 'POST':
        try:
            # Extract form data
            form_data = {
                'name': request.form.get('name'),
                'category': request.form.get('category'),
                'quantity': request.form.get('quantity'),
                'price': request.form.get('price')
            }
            
            # Apply similar validation as the API route
            try:
                quantity = int(form_data['quantity'])
                if quantity < 0:
                    flash('Quantity must be non-negative', 'danger')
                    return render_template('edit.html', product=item, year=datetime.now().year)
                form_data['quantity'] = quantity
            except ValueError:
                flash('Invalid quantity', 'danger')
                return render_template('edit.html', product=item, year=datetime.now().year)

            try:
                price = float(form_data['price'])
                if price < 0:
                    flash('Price must be non-negative', 'danger')
                    return render_template('edit.html', product=item, year=datetime.now().year)
                form_data['price'] = price
            except ValueError:
                flash('Invalid price', 'danger')
                return render_template('edit.html', product=item, year=datetime.now().year)

            # Update fields using the same pattern as the API route
            for key, value in form_data.items():
                if hasattr(item, key):
                    setattr(item, key, value)

            db.session.commit()
            flash('Item updated successfully', 'success')
            return redirect(url_for('inventory'))

        except Exception as e:
            # Error handling like in the API route
            db.session.rollback()
            flash(f'Error updating item: {str(e)}', 'danger')
            return render_template('edit.html', product=item, year=datetime.now().year)

# Serve inventory.js
@app.route('/static/js/inventory.js')
def serve_inventory_js():
    return send_from_directory('static/js', 'inventory.js')

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('errors/500.html'), 500

# Initialize database
def init_db():
    with app.app_context():
        try:
            db.create_all()
            print("Database initialized successfully")
        except Exception as e:
            print(f"Error initializing database: {str(e)}")


if __name__ == '__main__':
    init_db()  
    app.run(debug=True)