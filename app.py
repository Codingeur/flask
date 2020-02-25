from flask import Flask,render_template,abort, make_response,request,redirect,url_for
import pdfkit
from datetime import datetime
from flask_wtf import FlaskForm
from flask_bootstrap import Bootstrap
from wtforms.validators import InputRequired ,Email,Length
from wtforms import StringField, PasswordField, BooleanField
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
from werkzeug.utils import secure_filename
import time


app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database/base.sqlite3'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'



class User(UserMixin,db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

    def __repr__(self):
        return '<Post %s>' % self.username

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(80), nullable=False)
    content = db.Column(db.Text, nullable=False)


    def __repr__(self):
        return '<Post %s>' % self.title


class LoginForm(FlaskForm):
    username = StringField('Identifiant', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Mot de passe', validators=[InputRequired(), Length(min=4, max=90)])
    remember = BooleanField('Se rappeler de moi')

class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message='invalide email'), Length(min=4, max=80)])
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=4, max=90)])

class FormPdf(FlaskForm):
    prenom = StringField('prenom', validators=[InputRequired(), Length(min=4, max=15)])
    nom = PasswordField('non', validators=[InputRequired(), Length(min=4, max=90)])
    


@app.route('/upload', methods =['GET', 'POST'])
def upload_file():
    user_name = current_user.username
    url = os.path.join( "blog/" + user_name + "/")
    
    if not os.path.exists(os.path.join( "blog/static/" + user_name)):
            os.makedirs(os.path.join( "blog/static/" + user_name))

    list = (os.listdir(os.path.join( "blog/static/" + user_name )))
    if request.method == 'POST':
        image = request.files['profile']
        ok = image.save(os.path.join( "blog/static/" + user_name + "/" + image.filename))
        return render_template('page/upload.html', list=list, user_name=user_name)

        return render_template('page/upload.html', list=list, user_name=user_name)
    

    return render_template('page/upload.html', list = list, user_name=user_name)


@app.route('/delete_file/<fichier>', methods =['GET', 'POST'])
def delete_file(fichier):

    os.remove(os.path.join( "blog/static/" + current_user.username + "/" + fichier))

    return redirect(url_for('upload_file'))


@app.route('/pdf/', methods =['GET', 'POST'])
def pdf():
    form = FormPdf()

    if form.validate_on_submit():
        rendered = render_template('page/test_pdf.html', nom= form.nom.data, prenom=form.prenom.data)
        pdf = pdfkit.from_string(rendered, False)

        response = make_response(pdf)
        response.headers['Content-type'] = 'application/pdf'
        response.headers['Content-Disposition'] = 'inline; filename=output.pdf'

        return response

    return render_template('page/pdf.html', form=form)


@app.route('/pdf_template/', methods =['GET', 'POST'])
def pdf_template():

    rendered = render_template('page/test_pdf.html', nom= nom, prenom=prenom)
    pdf = pdfkit.from_string(rendered, False)

    response = make_response(pdf)
    response.headers['Content-type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'inline; filename=output.pdf'

    return response


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)
    
@app.route('/')
@login_required
def home():
    return render_template('page/home.html')


@app.route('/signup', methods =['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256') 
        new_user = User(username = form.username.data, email = form.email.data, password = hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return '<h4> votre compte a bien ete créer </h4>'

    return render_template('page/signup.html', form=form)



@app.route('/login', methods =['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username = form.username.data).first()
        if user :
            if check_password_hash(user.password,form.password.data):
                login_user(user, remember= form.remember.data)

                return redirect(url_for('post_index'))

        return "Pseudo ou mot de passe invalide"

    return render_template('page/login.html', form=form)



@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/about')
@login_required
def about():
    return render_template('page/about.html')

@app.route('/contact')
@login_required
def contact():
    return render_template('page/contact.html')


@app.route('/blog/')
@login_required
def post_index():
    posts = Post.query.all()
    return render_template('post/index.html')


@app.route('/blog/post/<int:id>')
@login_required
def post_show(id):
    post = Post.query.get(id)
    if post is None:
        abort(404)
    return render_template('post/show.html', post = post)


@app.errorhandler(404)
def page_not_found(error):
    return render_template('page/error404.html'),404

@app.context_processor
def pluriel():
    def pluralize(count , singular, plural=None):
        if not isinstance(count, int):
            raise ValueError(' "()" must be an integer'. format(count))

        if plural is None:
            plural = singular + "s"

        if count == 1:
            result = singular
        else :
            result = plural

        return"{} {}".format(count, result)
    return dict(pluralize=pluralize)

@app.context_processor
def date_now():
    return {'now' : datetime.now()}


if __name__ == '__main__' :
    db.create_all()
