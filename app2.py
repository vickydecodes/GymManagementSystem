from flask import Flask, render_template, flash, redirect, url_for, request, session, g
import sqlite3
from wtforms import Form, StringField, TextAreaField, PasswordField, validators, RadioField, SelectField, IntegerField
from wtforms.fields import DateField
from passlib.hash import sha256_crypt
from functools import wraps
from datetime import datetime

app = Flask(__name__)

DATABASE = 'gym.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Nice try, Tricks don\'t work, bud!! Please Login :)', 'danger')
            return redirect(url_for('login'))
    return wrap

def is_trainor(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if session['prof'] == 3:
            return f(*args, **kwargs)
        else:
            flash('You are probably not a trainor!!, Are you?', 'danger')
            return redirect(url_for('login'))
    return wrap

def is_admin(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if session['prof'] == 1:
            return f(*args, **kwargs)
        else:
            flash('You are probably not an admin!!, Are you?', 'danger')
            return redirect(url_for('login'))
    return wrap

def is_recep_level(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if session['prof'] <= 2:
            return f(*args, **kwargs)
        else:
            flash('You are probably not an authorised to view that page!!', 'danger')
            return redirect(url_for('login'))
    return wrap

@app.route('/')
def index():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password_candidate = request.form['password']

        cur = get_db().cursor()
        cur.execute('SELECT * FROM info WHERE username = ?', (username,))
        data = cur.fetchone()

        if data:
            password = data['password']
            if sha256_crypt.verify(password_candidate, password):
                session['logged_in'] = True
                session['username'] = username
                session['prof'] = data['prof']
                flash('You are logged in', 'success')
                if session['prof'] == 1:
                    return redirect(url_for('adminDash'))
                if session['prof'] == 3:
                    return redirect(url_for('trainorDash'))
                if session['prof'] == 2:
                    return redirect(url_for('recepDash'))
                return redirect(url_for('memberDash', username=username))
            else:
                error = 'Invalid login'
                return render_template('login.html', error=error)
        else:
            error = 'Username NOT FOUND'
            return render_template('login.html', error=error)
    return render_template('login.html')


class ChangePasswordForm(Form):
    old_password = PasswordField('Existing Password')
    new_password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords aren\'t matching pal!, check \'em')
    ])
    confirm = PasswordField('Confirm Password')


@app.route('/update_password/<string:username>', methods=['GET', 'POST'])
def update_password(username):
    form = ChangePasswordForm(request.form)
    if request.method == 'POST' and form.validate():
        new = form.new_password.data
        entered = form.old_password.data
        cur = get_db().cursor()
        cur.execute("SELECT password FROM info WHERE username = ?", (username,))
        old = cur.fetchone()['password']
        if sha256_crypt.verify(entered, old):
            cur.execute("UPDATE info SET password = ? WHERE username = ?", (sha256_crypt.encrypt(new), username))
            get_db().commit()
            flash('New password will be in effect from next login!!', 'info')
            return redirect(url_for('memberDash', username=session['username']))
        flash('Old password you entered is wrong!!, try again', 'warning')
    return render_template('updatePassword.html', form=form)


@app.route('/adminDash')
@is_logged_in
@is_admin
def adminDash():
    return render_template('adminDash.html')


values = []
choices = []


class AddTrainorForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=100)])
    username = StringField('Username', [validators.InputRequired(), validators.NoneOf(values=values, message="Username already taken, Please try another")])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords aren\'t matching pal!, check \'em')
    ])
    confirm = PasswordField('Confirm Password')
    street = StringField('Street', [validators.Length(min=1, max=100)])
    city = StringField('City', [validators.Length(min=1, max=100)])
    prof = 3
    phone = StringField('Phone', [validators.Length(min=1, max=100)])


@app.route('/addTrainor', methods=['GET', 'POST'])
@is_logged_in
@is_admin
def addTrainor():
    values.clear()
    cur = get_db().cursor()
    cur.execute("SELECT username FROM info")
    b = cur.fetchall()
    for row in b:
        values.append(row['username'])
    form = AddTrainorForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))
        street = form.street.data
        city = form.city.data
        phone = form.phone.data
        cur.execute("INSERT INTO info(name, username, password, street, city, prof, phone) VALUES(?,?,?,?,?,?,?)", (name, username, password, street, city, 3, phone))
        cur.execute("INSERT INTO trainors(username) VALUES(?)", (username,))
        get_db().commit()
        flash('You recruited a new Trainor!!', 'success')
        return redirect(url_for('adminDash'))
    return render_template('addTrainor.html', form=form)


class DeleteRecepForm(Form):
    username = SelectField(u'Choose which one you wanted to delete', choices=choices)


@app.route('/deleteTrainor', methods=['GET', 'POST'])
@is_logged_in
@is_admin
def deleteTrainor():
    choices.clear()
    cur = get_db().cursor()
    cur.execute("SELECT username FROM trainors")
    b = cur.fetchall()
    for row in b:
        choices.append((row['username'], row['username']))
    form = DeleteRecepForm(request.form)
    if len(choices) == 1:
        flash('You cannot remove your only Trainor!!', 'danger')
        return redirect(url_for('adminDash'))
    if request.method == 'POST':
        username = form.username.data
        cur.execute("SELECT username FROM trainors WHERE username != ?", (username,))
        b = cur.fetchall()
        new = b[0]['username']
        cur.execute("UPDATE members SET trainor = ? WHERE trainor = ?", (new, username))
        cur.execute("DELETE FROM trainors WHERE username = ?", (username,))
        cur.execute("DELETE FROM info WHERE username = ?", (username,))
        get_db().commit()
        choices.clear()
        flash('You removed your Trainor!!', 'success')
        return redirect(url_for('adminDash'))
    return render_template('deleteRecep.html', form=form)


@app.route('/addRecep', methods=['GET', 'POST'])
@is_logged_in
@is_admin
def addRecep():
    values.clear()
    cur = get_db().cursor()
    cur.execute("SELECT username FROM info")
    b = cur.fetchall()
    for row in b:
        values.append(row['username'])
    cur.close()

    form = AddTrainorForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))
        street = form.street.data
        city = form.city.data
        phone = form.phone.data

        cur = get_db().cursor()
        cur.execute(
            "INSERT INTO info(name, username, password, street, city, prof, phone) VALUES(?,?,?,?,?,?,?)",
            (name, username, password, street, city, 2, phone)
        )
        cur.execute("INSERT INTO receps(username) VALUES(?)", (username,))
        get_db().commit()
        cur.close()
        flash('You recruited a new Receptionist!!', 'success')
        return redirect(url_for('adminDash'))
    return render_template('addRecep.html', form=form)


class DeleteRecepForm(Form):
    username = SelectField(u'Choose which one you wanted to delete', choices=choices)


@app.route('/deleteRecep', methods=['GET', 'POST'])
@is_logged_in
@is_admin
def deleteRecep():
    choices.clear()
    cur = get_db().cursor()
    cur.execute("SELECT username FROM receps")
    b = cur.fetchall()
    for row in b:
        choices.append((row['username'], row['username']))

    if len(choices) == 1:
        flash('You cannot remove your only receptionist!!', 'danger')
        return redirect(url_for('adminDash'))

    form = DeleteRecepForm(request.form)
    if request.method == 'POST':
        username = form.username.data
        cur.execute("DELETE FROM receps WHERE username = ?", (username,))
        cur.execute("DELETE FROM info WHERE username = ?", (username,))
        get_db().commit()
        cur.close()
        choices.clear()
        flash('You removed your receptionist!!', 'success')
        return redirect(url_for('adminDash'))
    return render_template('deleteRecep.html', form=form)

class AddEquipForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=100)])
    count = IntegerField('Count', [validators.NumberRange(min=1, max=25)])


@app.route('/addEquip', methods=['GET', 'POST'])
@is_logged_in
@is_admin
def addEquip():
    form = AddEquipForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        count = form.count.data
        cur = get_db().cursor()
        cur.execute("SELECT name FROM equip")
        equips = [row['name'] for row in cur.fetchall()]

        if name in equips:
            cur.execute("UPDATE equip SET count = count + ? WHERE name = ?", (count, name))
        else:
            cur.execute("INSERT INTO equip(name, count) VALUES(?,?)", (name, count))

        get_db().commit()
        cur.close()
        flash('You added a new Equipment!!', 'success')
        return redirect(url_for('adminDash'))
    return render_template('addEquip.html', form=form)


class RemoveEquipForm(Form):
    name = RadioField('Name', choices=choices)
    count = IntegerField('Count', [validators.InputRequired()])


@app.route('/removeEquip', methods=['GET', 'POST'])
@is_logged_in
@is_admin
def removeEquip():
    choices.clear()
    cur = get_db().cursor()
    cur.execute("SELECT name FROM equip")
    b = cur.fetchall()
    for row in b:
        choices.append((row['name'], row['name']))

    form = RemoveEquipForm(request.form)
    if request.method == 'POST' and form.validate():
        cur.execute("SELECT * FROM equip WHERE name = ?", (form.name.data,))
        data = cur.fetchone()
        num = data['count']

        if 0 < form.count.data <= num:
            cur.execute("UPDATE equip SET count = count - ? WHERE name = ?", (form.count.data, form.name.data))
            get_db().commit()
            cur.close()
            choices.clear()
            flash('You successfully removed some of your equipment!!', 'success')
            return redirect(url_for('adminDash'))
        else:
            flash('You must enter a valid number', 'danger')
    return render_template('removeEquip.html', form=form)


choices2 = []

class AddMemberForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.InputRequired(), validators.NoneOf(values=values, message="Username already taken")])
    password = PasswordField('Password', [validators.DataRequired(), validators.EqualTo('confirm', message='Passwords do not match')])
    confirm = PasswordField('Confirm Password')
    plan = RadioField('Select Plan', choices=choices)
    trainor = SelectField('Select Trainor', choices=choices2)
    street = StringField('Street', [validators.Length(min=1, max=100)])
    city = StringField('City', [validators.Length(min=1, max=100)])
    phone = StringField('Phone', [validators.Length(min=1, max=100)])


@app.route('/addMember', methods=['GET', 'POST'])
@is_logged_in
@is_recep_level
def addMember():
    choices.clear()
    choices2.clear()
    cur = get_db().cursor()

    cur.execute("SELECT username FROM info")
    for row in cur.fetchall():
        values.append(row['username'])

    cur.execute("SELECT DISTINCT name FROM plans")
    for row in cur.fetchall():
        choices.append((row['name'], row['name']))

    cur.execute("SELECT username FROM trainors")
    for row in cur.fetchall():
        choices2.append((row['username'], row['username']))

    cur.close()
    form = AddMemberForm(request.form)

    if request.method == 'POST' and form.validate():
        name = form.name.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))
        street = form.street.data
        city = form.city.data
        phone = form.phone.data
        plan = form.plan.data
        trainor = form.trainor.data

        cur = get_db().cursor()
        cur.execute("INSERT INTO info(name, username, password, street, city, prof, phone) VALUES(?,?,?,?,?,?,?)",
                    (name, username, password, street, city, 4, phone))
        cur.execute("INSERT INTO members(username, plan, trainor) VALUES(?,?,?)", (username, plan, trainor))
        get_db().commit()
        cur.close()
        choices.clear()
        choices2.clear()
        flash('You added a new member!!', 'success')

        if session['prof'] == 1:
            return redirect(url_for('adminDash'))
        return redirect(url_for('recepDash'))

    return render_template('addMember.html', form=form)


@app.route('/deleteMember', methods=['GET', 'POST'])
@is_logged_in
@is_recep_level
def deleteMember():
    choices.clear()
    cur = get_db().cursor()
    cur.execute("SELECT username FROM members")
    for row in cur.fetchall():
        choices.append((row['username'], row['username']))

    form = DeleteRecepForm(request.form)
    if request.method == 'POST':
        username = form.username.data
        cur.execute("DELETE FROM members WHERE username = ?", (username,))
        cur.execute("DELETE FROM info WHERE username = ?", (username,))
        get_db().commit()
        cur.close()
        choices.clear()
        flash('You deleted a member from the GYM!!', 'success')

        if session['prof'] == 1:
            return redirect(url_for('adminDash'))
        return redirect(url_for('recepDash'))
    return render_template('deleteRecep.html', form=form)


class trainorForm(Form):
    name = RadioField('Select Username', choices=choices)
    date = DateField('Date', format='%Y-%m-%d')
    report = StringField('Report', [validators.InputRequired()])
    rate = RadioField('Result', choices=[('good','good'),('average','average'),('poor','poor')])

@app.route('/trainorDash', methods=['GET','POST'])
@is_logged_in
@is_trainor
def trainorDash():
    choices.clear()
    cur = get_db().cursor()

    # Fetch equipment
    cur.execute("SELECT name, count FROM equip")
    equips = cur.fetchall()

    # Fetch members under this trainor
    cur.execute("SELECT username FROM members WHERE trainor = ?", (session['username'],))
    members_under = cur.fetchall()

    # Populate choices for the form
    cur.execute("SELECT username FROM members WHERE trainor = ?", (session['username'],))
    for row in cur.fetchall():
        choices.append((row['username'], row['username']))
    cur.close()

    form = trainorForm(request.form)

    if request.method == 'POST':
        date = form.date.data
        username = form.name.data
        report = form.report.data
        rate = form.rate.data

        rate_map = {'good': 1, 'average': 2, 'poor': 3}
        rate_val = rate_map.get(rate, 2)

        if datetime.now().date() < date:
            flash('You cannot predict future, buoy!!', 'warning')
            choices.clear()
            return redirect(url_for('trainorDash'))

        cur = get_db().cursor()
        cur.execute("SELECT date FROM progress WHERE username = ?", (username,))
        entered = [row['date'] for row in cur.fetchall()]

        if date in entered:
            cur.execute("UPDATE progress SET daily_result = ?, rate = ? WHERE username = ? AND date = ?",
                        (report, rate_val, username, date))
        else:
            cur.execute("INSERT INTO progress(username, date, daily_result, rate) VALUES(?,?,?,?)",
                        (username, date, report, rate_val))

        get_db().commit()
        cur.close()
        choices.clear()
        flash('Progress updated and Reported', 'info')
        return redirect(url_for('trainorDash'))

    return render_template('trainorDash.html', equips=equips, form=form, members=members_under)


class UpdatePlanForm(Form):
    name = StringField('Plan Name', [validators.Length(min=1, max=50)])
    exercise = StringField('Exercise', [validators.Length(min=1, max=100)])
    reps = IntegerField('Reps', [validators.NumberRange(min=1, max=20)])
    sets = IntegerField('Sets', [validators.NumberRange(min=1, max=20)])

@app.route('/updatePlans', methods=['GET','POST'])
@is_trainor
def updatePlans():
    form = UpdatePlanForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        exercise = form.exercise.data
        reps = form.reps.data
        sets = form.sets.data

        cur = get_db().cursor()
        cur.execute("SELECT name, exercise FROM plans WHERE name = ? AND exercise = ?", (name, exercise))
        result = cur.fetchall()

        if len(result) > 0:
            cur.execute("UPDATE plans SET sets = ?, reps = ? WHERE name = ? AND exercise = ?", (sets, reps, name, exercise))
        else:
            cur.execute("INSERT INTO plans(name, exercise, sets, reps) VALUES(?,?,?,?)", (name, exercise, sets, reps))

        get_db().commit()
        cur.close()
        flash('You have updated the plan schemes', 'success')
        return redirect(url_for('trainorDash'))

    return render_template('addPlan.html', form=form)


@app.route('/memberDash/<string:username>')
@is_logged_in
def memberDash(username):
    if session['prof'] == 4 and username != session['username']:
        flash("You aren't authorised to view other's Dashboards", 'danger')
        return redirect(url_for('memberDash', username=session['username']))

    cur = get_db().cursor()
    cur.execute("SELECT plan FROM members WHERE username = ?", (username,))
    plan = cur.fetchone()['plan']

    cur.execute("SELECT exercise, reps, sets FROM plans WHERE name = ?", (plan,))
    scheme = cur.fetchall()

    cur.execute("SELECT date, daily_result, rate FROM progress WHERE username = ? ORDER BY date DESC", (username,))
    progress = cur.fetchall()

    result = [int(row['rate']) for row in progress]
    good = result.count(1)
    average = result.count(2)
    poor = result.count(3)
    total = good + average + poor

    good_pct = round((good/total)*100,2) if total else 0
    average_pct = round((average/total)*100,2) if total else 0
    poor_pct = round((poor/total)*100,2) if total else 0

    cur.close()
    return render_template('memberDash.html', user=username, plan=plan, scheme=scheme,
                           progress=progress, good=good_pct, average=average_pct, poor=poor_pct)


@app.route('/profile/<string:username>')
@is_logged_in
def profile(username):
    if username == session['username'] or session['prof'] in (1,2):
        cur = get_db().cursor()
        cur.execute("SELECT * FROM info WHERE username = ?", (username,))
        result = cur.fetchone()
        cur.close()
        return render_template('profile.html', result=result)

    flash("You cannot view other's profile", 'warning')
    if session['prof'] == 3:
        return redirect(url_for('trainorDash'))
    return redirect(url_for('memberDash', username=username))


class EditForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    street = StringField('Street', [validators.Length(min=1, max=100)])
    city = StringField('City', [validators.Length(min=1, max=100)])
    phone = StringField('Phone', [validators.Length(min=1, max=100)])

@app.route('/edit_profile/<string:username>', methods=['GET','POST'])
@is_logged_in
def edit_profile(username):
    if username != session['username']:
        flash("You aren't authorised to edit other's details", 'warning')
        if session['prof']==4: return redirect(url_for('memberDash', username=username))
        if session['prof']==1: return redirect(url_for('adminDash'))
        if session['prof']==2: return redirect(url_for('recepDash', username=username))
        if session['prof']==3: return redirect(url_for('trainorDash', username=username))

    cur = get_db().cursor()
    cur.execute("SELECT * FROM info WHERE username = ?", (username,))
    result = cur.fetchone()

    form = EditForm(request.form)
    form.name.data = result['name']
    form.street.data = result['street']
    form.city.data = result['city']
    form.phone.data = result['phone']
    cur.close()

    if request.method == 'POST' and form.validate():
        cur = get_db().cursor()
        cur.execute("UPDATE info SET name=?, street=?, city=?, phone=? WHERE username=?",
                    (form.name.data, form.street.data, form.city.data, form.phone.data, username))
        get_db().commit()
        cur.close()
        flash('You successfully updated your profile!!', 'success')

        if session['prof']==4: return redirect(url_for('memberDash', username=username))
        if session['prof']==1: return redirect(url_for('adminDash'))
        if session['prof']==2: return redirect(url_for('recepDash', username=username))
        if session['prof']==3: return redirect(url_for('trainorDash', username=username))

    return render_template('edit_profile.html', form=form)

@app.route('/viewDetails')
def viewDetails():
    cur = get_db().cursor()
    cur.execute("SELECT username FROM info WHERE username != ?", (session['username'],))
    result = cur.fetchall()
    cur.close()
    return render_template('viewDetails.html', result=result)


@app.route('/logout')
@is_logged_in
def logout():
	session.clear()
	flash('You are now logged out', 'success')
	return redirect(url_for('login'))


if __name__ == "__main__":
    app.secret_key = '528491@JOKER'
    app.run(debug=True)

