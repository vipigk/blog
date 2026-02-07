import pymysql
pymysql.install_as_MySQLdb()

from flask import Flask, render_template, flash, redirect, url_for, session, request
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)

# Security Config: In a real app, use environment variables!
app.secret_key = 'REPLACE_THIS_WITH_A_LONG_RANDOM_STRING' 

# Config MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '@bcd#123'
app.config['MYSQL_DB'] = 'flaskapp'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql = MySQL(app)

# --- AUTH DECORATOR ---
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap

# --- ROUTES ---

@app.route('/')
def index():
    return render_template('home.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/articles')
def articles():
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT * FROM articles")
    articles = cur.fetchall()
    if result > 0:
        return render_template('articles.html', articles=articles)
    else:
        return render_template('articles.html', msg='No Articles Found')
    cur.close()

@app.route('/article/<string:id>/')
def article(id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM articles WHERE id = %s", [id])
    article = cur.fetchone()
    cur.close()
    return render_template('article.html', article=article)

# --- USER MANAGEMENT ---

class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        # Use Werkzeug for modern hashing
        password = generate_password_hash(str(form.password.data))

        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users(name, email, username, password) VALUES(%s, %s, %s, %s)", 
                   (name, email, username, password))
        mysql.connection.commit()
        cur.close()

        flash('You are now registered and can log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password_candidate = request.form['password']

        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM users WHERE username = %s", [username])

        if result > 0:
            data = cur.fetchone()
            password = data['password']

            if check_password_hash(password, password_candidate):
                session['logged_in'] = True
                session['username'] = username
                flash('You are now logged in', 'success')
                return redirect(url_for('dashboard'))
            else:
                return render_template('login.html', error='Invalid login')
        else:
            return render_template('login.html', error='Username not found')
        cur.close()
    return render_template('login.html')

@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))

# --- DASHBOARD & ARTICLES ---

@app.route('/dashboard')
@is_logged_in
def dashboard():
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT * FROM articles WHERE author = %s", [session['username']])
    articles = cur.fetchall()
    cur.close()
    if result > 0:
        return render_template('dashboard.html', articles=articles)
    else:
        return render_template('dashboard.html', msg='No Articles Found')

class ArticleForm(Form):
    title = StringField('Title', [validators.Length(min=1, max=200)])
    body = TextAreaField('Body', [validators.Length(min=30)])

@app.route('/add_article', methods=['GET', 'POST'])
@is_logged_in
def add_article():
    form = ArticleForm(request.form)
    if request.method == 'POST' and form.validate():
        title = form.title.data
        body = form.body.data
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO articles(title, body, author) VALUES(%s, %s, %s)",
                   (title, body, session['username']))
        mysql.connection.commit()
        cur.close()
        flash('Article Created', 'success')
        return redirect(url_for('dashboard'))
    return render_template('add_article.html', form=form)

@app.route('/edit_article/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def edit_article(id):
    cur = mysql.connection.cursor()
    # Check if article exists AND if the current user is the author
    result = cur.execute("SELECT * FROM articles WHERE id = %s AND author = %s", [id, session['username']])
    article = cur.fetchone()
    
    if not article:
        flash('Permission denied or article not found', 'danger')
        return redirect(url_for('dashboard'))

    form = ArticleForm(request.form)
    form.title.data = article['title']
    form.body.data = article['body']

    if request.method == 'POST' and form.validate():
        title = request.form['title']
        body = request.form['body']
        cur.execute("UPDATE articles SET title=%s, body=%s WHERE id=%s AND author=%s", (title, body, id, session['username']))
        mysql.connection.commit()
        cur.close()
        flash('Article Updated', 'success')
        return redirect(url_for('dashboard'))
    
    cur.close()
    return render_template('edit_article.html', form=form)

@app.route('/delete_article/<string:id>', methods=['POST'])
@is_logged_in
def delete_article(id):
    cur = mysql.connection.cursor()
    # Ensure user owns the article before deleting
    cur.execute("DELETE FROM articles WHERE id = %s AND author = %s", [id, session['username']])
    mysql.connection.commit()
    cur.close()
    flash('Article Deleted', 'success')
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    # DEBUG is now set to False for safety
    app.run(debug=False)
