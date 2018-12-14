#import statements
import os
import requests
import json
from flask import Flask, render_template, session, redirect, request, url_for, flash
from flask_script import Manager, Shell
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, FileField, PasswordField, BooleanField, SelectMultipleField, ValidationError
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate, MigrateCommand
from werkzeug.security import generate_password_hash, check_password_hash

#imports for login management
from flask_login import LoginManager, login_required, logout_user, login_user, UserMixin, current_user



#application configurations
app = Flask(__name__)
app.debug = True
app.use_reloader = True
app.config['SECRET_KEY'] = 'hardtoguesstring'
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get('DATABASE_URL') or "postgresql://localhost/lsoenen364finaldb"
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

#additional setup
manager = Manager(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
manager.add_command('db', MigrateCommand)

#login configurations setup
login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'
login_manager.init_app(app)

#attribution tables
user_collection = db.Table('user_collection',db.Column('team_id', db.Integer, db.ForeignKey('teams.id')),db.Column('collection_id',db.Integer, db.ForeignKey('personalteams.id')))

#models
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, index=True)
    email = db.Column(db.String(50), unique=True, index=True)
    password_hash = db.Column(db.String(100))
    personal_teamsID = db.Column(db.Integer, db.ForeignKey('personalteams.id'))

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class Team(db.Model):
    __tablename__ = "teams"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    players = db.relationship('Player', backref='Player')


class PersonalTeamCollection(db.Model):
    __tablename__ = "personalteams"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    teams = db.relationship('Team', secondary=user_collection,backref=db.backref('personalteams',lazy='dynamic'))

class Player(db.Model):
    __tablename__ = "players"
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String)
    last_name = db.Column(db.String)
    position = db.Column(db.String)
    team_id = db.Column(db.Integer, db.ForeignKey('teams.id'))



#forms
class RegistrationForm(FlaskForm):
    email = StringField('Email:', validators=[Required(),Length(1,50),Email()])
    username = StringField('Username:', validators=[Required(), Length(1,50), Regexp('^[A-Za-z][A-Za-z0-9_.]*$',0,'Usernames must have only letters, numbers, dots or underscores')])
    password = PasswordField('Password:', validators=[Required(),EqualTo('password2',message="Passwords must match")])
    password2 = PasswordField("Confirm Password:",validators=[Required()])
    submit = SubmitField('Register User')

    def validate_email(self,field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self,field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already taken')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[Required(), Length(1,50), Email()])
    password = PasswordField('Password', validators=[Required()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')


class TeamForm(FlaskForm):
    search = StringField("Enter a team abbreviation to see their roster: ", validators = [Required()])
    submit = SubmitField('Submit')


#helper functions
def get_or_create_team(team):
    team_info = Team.query.filter_by(name=team).first()
    if team_info:
        player_lst = []
        all_players = Player.query.all()
        for player in all_players:
            if player.team_id == team_info.id:
                player_lst.append(player)
        return render_template('roster.html', players = player_lst)

    else:
        api_key = 'gmjs72z9r685mj339k2s3cs7'
        base_url = "http://api.sportradar.us/ncaafb-t1/teams/" + team + "/roster.json?api_key=" + api_key
        response = requests.get(base_url)
        text = response.text
        python_obj = json.loads(text)
        team_name = python_obj['id']
        team_info = Team(name=team_name)
        db.session.add(team_info)
        db.session.commit()

        players = python_obj['players']
        for player in players:
            player_first_name = player['name_first']
            player_last_name = player['name_last']
            player_position = player['position']
            player_info = Player(first_name=player_first_name, last_name=player_last_name, position=player_position, team_id=team_info.id)
            db.session.add(player_info)
            db.session.commit()

            player_lst = []
            all_players = Player.query.all()
            for player in all_players:
                if player.team_id == team_info.id:
                    player_lst.append(player)

        return render_template('roster.html', players = player_lst)

def get_or_create_personalteams_list():
    personalteams_collectionn = PersonalTeamCollection.query.filter_by(name, current_user, team_list=[])
    if personalteams_collection:
        return personalteams_collection
    else:
        personalteams_collection = PersonalTeamCollection(name=name, user_id=current_user, teams=team_list)
        db.session.add(personalteams_collection)
        db.session.commit()
        return personalteams_collection

def show_all_teams():
    team_lst = []
    all_teams = Team.query.all()
    for team in all_teams:
        team_lst.append(team)
    return team_lst





#view functions
@app.route('/',methods=["GET","POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('teamform'))
        flash('Invalid username or password.')
    return render_template('base.html',form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out')
    return redirect(url_for('login'))

@app.route('/register',methods=["GET","POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,username=form.username.data,password=form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('You can now log in!')
        return redirect(url_for('login'))
    return render_template('register.html',form=form)


@app.route('/team_form', methods=["GET", "POST"])
@login_required
def teamform():
    form = TeamForm()
    if form.validate_on_submit():
        team = get_or_create_team(team=form.search.data)
        return team
    return render_template('teamform.html', form=form)

@app.route('/all_teams', methods=["GET", "POST"])
def allteams():
    all_teams = show_all_teams()
    return render_template('allteams.html', teams=all_teams)






if __name__ == '__main__':
    db.create_all()
    manager.run()
