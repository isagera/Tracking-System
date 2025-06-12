from flask import Flask, render_template, request, redirect, url_for, flash, send_file, session, make_response
from flask_sqlalchemy import SQLAlchemy
import datetime
import pandas as pd
import io
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import or_ # Import or_ for multiple field search
from sqlalchemy import cast # Import cast to correctly convert column types for querying
from sqlalchemy import String as SQLAString # Alias String from SQLAlchemy for clarity in cast
from functools import wraps # Import wraps for decorator

app = Flask(__name__)

# --- Database Configuration ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///personal_files.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
# --- End Database Configuration ---

app.secret_key = 'your_super_secret_key_here' # Keep this secret and complex!

# --- Database Models ---
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User {self.username}>"

class File(db.Model):
    __tablename__ = 'files'
    id = db.Column(db.Integer, primary_key=True)
    F_No = db.Column(db.Integer, unique=True, nullable=False)
    Rank = db.Column(db.String(100), nullable=True)
    Names = db.Column(db.String(200), nullable=False)
    Origin = db.Column(db.String(200), nullable=True)
    Destination = db.Column(db.String(200), nullable=True)
    Reason = db.Column(db.Text, nullable=True) # Renamed from Comment
    Action_Taken = db.Column(db.String(200), nullable=True) # New column
    Date_Received = db.Column(db.String(10), nullable=False)
    Date_Returned = db.Column(db.String(10), nullable=True)
    Return_Office = db.Column(db.String(200), nullable=True)

    def __repr__(self):
        return f"<File {self.F_No} - {self.Names}>"

# Helper function to validate date format (YYYY-MM-DD)
def is_valid_date(date_str):
    if not date_str:
        return True
    try:
        datetime.datetime.strptime(date_str, '%Y-%m-%d')
        return True
    except ValueError:
        return False

# Decorator to prevent caching
def no_cache(view):
    @wraps(view)
    def no_cache_view(*args, **kwargs):
        response = make_response(view(*args, **kwargs))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '-1'
        return response
    return no_cache_view

# --- New Registration Route ---
@app.route('/register', methods=['GET', 'POST'])
@no_cache # Apply no_cache to registration page
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not username or not password or not confirm_password:
            flash('All fields are required.', 'danger')
            return render_template('register.html', username=username)

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html', username=username)

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
            return render_template('register.html', username=username)

        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')
# --- End New Registration Route ---

# --- Login & Logout Routes ---
@app.route('/login', methods=['GET', 'POST'])
@no_cache # Apply no_cache to login page
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            session['logged_in'] = True
            session['username'] = user.username
            flash(f'Logged in successfully as {user.username}!', 'success')
            return redirect(url_for('index')) # Redirect to the main file list
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@no_cache # Apply no_cache to logout route
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))
# --- End Login & Logout Routes ---

# --- Routes (Modified to require login and no_cache) ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or not session['logged_in']:
            flash('Please log in to access this page.', 'info')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
@app.route('/files')
@login_required
@no_cache # Apply no_cache to index page
def index():
    query = request.args.get('query', '').strip()
    files = []

    if query:
        search_pattern = f"%{query}%"
        try:
            query_int = int(query)
            files = File.query.filter(File.F_No == query_int).all()
        except ValueError:
            # If query is not an integer, search in other string fields
            files = File.query.filter(
                or_(
                    cast(File.F_No, SQLAString).ilike(search_pattern),
                    File.Rank.ilike(search_pattern),
                    File.Names.ilike(search_pattern),
                    File.Origin.ilike(search_pattern),
                    File.Destination.ilike(search_pattern),
                    File.Reason.ilike(search_pattern), # Renamed from Comment
                    File.Action_Taken.ilike(search_pattern), # Added Action_Taken to search
                    File.Return_Office.ilike(search_pattern)
                )
            ).all()

        if not files:
            flash(f"No files found matching your search for '{query}'.", 'info')
    else:
        files = File.query.all()

    return render_template('index.html', files=files, query=query)


@app.route('/add_file', methods=['GET', 'POST'])
@login_required
@no_cache # Apply no_cache to add_file page
def add_file():
    if request.method == 'POST':
        f_no = request.form.get('f_no')
        rank = request.form.get('rank')
        names = request.form.get('names')
        origin = request.form.get('origin')
        destination = request.form.get('destination')
        reason = request.form.get('reason') # Renamed from comment
        action_taken = request.form.get('action_taken') # New field
        date_received = request.form.get('date_received')
        date_returned = request.form.get('date_returned')
        return_office = request.form.get('return_office')

        if not f_no or not names or not date_received:
            flash('File Number, Names, and Date Received are required.', 'danger')
            return render_template('add_file.html', file={
                'F_No': f_no, 'Rank': rank, 'Names': names, 'Origin': origin,
                'Destination': destination, 'Reason': reason, # Renamed
                'Action_Taken': action_taken, # Added
                'Date_Received': date_received,
                'Date_Returned': date_returned, 'Return_Office': return_office
            })

        try:
            f_no_int = int(f_no)
        except ValueError:
            flash('File Number must be an integer.', 'danger')
            return render_template('add_file.html', file={
                'F_No': f_no, 'Rank': rank, 'Names': names, 'Origin': origin,
                'Destination': destination, 'Reason': reason, # Renamed
                'Action_Taken': action_taken, # Added
                'Date_Received': date_received,
                'Date_Returned': date_returned, 'Return_Office': return_office
            })

        existing_file = File.query.filter_by(F_No=f_no_int).first()
        if existing_file:
            flash(f'File with F/No {f_no_int} already exists. Please use a different file number.', 'danger')
            return render_template('add_file.html', file={
                'F_No': f_no, 'Rank': rank, 'Names': names, 'Origin': origin,
                'Destination': destination, 'Reason': reason, # Renamed
                'Action_Taken': action_taken, # Added
                'Date_Received': date_received,
                'Date_Returned': date_returned, 'Return_Office': return_office
            })

        if not is_valid_date(date_received):
            flash('Invalid format for Date Received. Use YYYY-MM-DD.', 'danger')
            return render_template('add_file.html', file={
                'F_No': f_no, 'Rank': rank, 'Names': names, 'Origin': origin,
                'Destination': destination, 'Reason': reason, # Renamed
                'Action_Taken': action_taken, # Added
                'Date_Received': date_received,
                'Date_Returned': date_returned, 'Return_Office': return_office
            })

        if date_returned and not is_valid_date(date_returned):
            flash('Invalid format for Date Returned. Use YYYY-MM-DD.', 'danger')
            return render_template('add_file.html', file={
                'F_No': f_no, 'Rank': rank, 'Names': names, 'Origin': origin,
                'Destination': destination, 'Reason': reason, # Renamed
                'Action_Taken': action_taken, # Added
                'Date_Received': date_received,
                'Date_Returned': date_returned, 'Return_Office': return_office
            })

        new_file = File(
            F_No=f_no_int,
            Rank=rank if rank else None,
            Names=names,
            Origin=origin if origin else None,
            Destination=destination if destination else None,
            Reason=reason if reason else None, # Renamed
            Action_Taken=action_taken if action_taken else None, # Added
            Date_Received=date_received,
            Date_Returned=date_returned if date_returned else None,
            Return_Office=return_office if return_office else None
        )
        db.session.add(new_file)
        db.session.commit()

        flash(f'File {f_no_int} added successfully!', 'success')
        return redirect(url_for('index'))
    return render_template('add_file.html', file={})

@app.route('/edit_file/<int:file_no>', methods=['GET', 'POST'])
@login_required
@no_cache # Apply no_cache to edit_file page
def edit_file(file_no):
    file_to_edit = File.query.filter_by(F_No=file_no).first()
    if not file_to_edit:
        flash('File not found.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        file_to_edit.Rank = request.form.get('rank')
        file_to_edit.Names = request.form.get('names')
        file_to_edit.Origin = request.form.get('origin')
        file_to_edit.Destination = request.form.get('destination')
        file_to_edit.Reason = request.form.get('reason') # Renamed from comment
        file_to_edit.Action_Taken = request.form.get('action_taken') # New field
        file_to_edit.Date_Received = request.form.get('date_received')
        file_to_edit.Date_Returned = request.form.get('date_returned')
        file_to_edit.Return_Office = request.form.get('return_office')

        if not file_to_edit.Names or not file_to_edit.Date_Received:
            flash('Names and Date Received are required.', 'danger')
            return render_template('edit_file.html', file=file_to_edit)

        if not is_valid_date(file_to_edit.Date_Received):
            flash('Invalid format for Date Received. Use YYYY-MM-DD.', 'danger')
            return render_template('edit_file.html', file=file_to_edit)

        if file_to_edit.Date_Returned and not is_valid_date(file_to_edit.Date_Returned):
            flash('Invalid format for Date Returned. Use YYYY-MM-DD.', 'danger')
            return render_template('edit_file.html', file=file_to_edit)

        db.session.commit()
        flash(f'File {file_to_edit.F_No} updated successfully!', 'success')
        return redirect(url_for('index'))

    return render_template('edit_file.html', file=file_to_edit)

@app.route('/delete_file/<int:file_no>', methods=['POST'])
@login_required
@no_cache # Apply no_cache to delete_file route
def delete_file(file_no):
    file_to_delete = File.query.filter_by(F_No=file_no).first()
    if file_to_delete:
        db.session.delete(file_to_delete)
        db.session.commit()
        flash(f'File {file_no} deleted successfully.', 'success')
    else:
        flash(f'File {file_no} not found.', 'danger')
    return redirect(url_for('index'))

@app.route('/download_excel')
@login_required
@no_cache # Apply no_cache to download_excel route
def download_excel():
    all_files = File.query.all()
    if not all_files:
        flash("No data to download.", 'info')
        return redirect(url_for('index'))

    data_for_df = []
    for file_obj in all_files:
        data_for_df.append({
            'F_No': file_obj.F_No,
            'Rank': file_obj.Rank,
            'Names': file_obj.Names,
            'Origin': file_obj.Origin,
            'Destination': file_obj.Destination,
            'Reason': file_obj.Reason, # Renamed
            'Action_Taken': file_obj.Action_Taken, # Added
            'Date_Received': file_obj.Date_Received,
            'Date_Returned': file_obj.Date_Returned,
            'Return_Office': file_obj.Return_Office
        })

    df = pd.DataFrame(data_for_df)

    column_order = [
        'F_No', 'Rank', 'Names', 'Origin', 'Destination',
        'Date_Received', 'Action_Taken', 'Reason', 'Date_Returned', 'Return_Office' # Reordered
    ]
    df = df[column_order]

    output = io.BytesIO()
    df.to_excel(output, index=False, engine='openpyxl')
    output.seek(0)

    return send_file(output, as_attachment=True, download_name='personal_files.xlsx', mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)