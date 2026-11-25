from flask import Flask, render_template, request, redirect, session, abort
import sqlite3, os, secrets
from pathlib import Path
from werkzeug.security import generate_password_hash, check_password_hash
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_SECURE=bool(os.environ.get('RENDER')), SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax')
DB = Path(os.environ.get('DATABASE_PATH', str(Path(__file__).with_name('college.db'))))
FIELDS = {
    'students': ['id','name','course','attendance','marks','fee','teacher'],
    'teachers': ['id','name','subject','salary','email'],
    'classes': ['id','subject','course','time','room','teacher'],
    'notices': ['id','title','message'],
    'users': ['id','username','password','role','person_id','recovery']
}
def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn
def setup():
    with db() as c:
        if c.execute("SELECT name FROM sqlite_master WHERE name='users'").fetchone():
            if 'recovery' not in [r[1] for r in c.execute('PRAGMA table_info(users)')]:
                c.execute("ALTER TABLE users ADD COLUMN recovery TEXT NOT NULL DEFAULT ''")
            return
        for table, fields in FIELDS.items():
            columns = ', '.join(f'{f} TEXT NOT NULL' for f in fields[1:])
            c.execute(f'CREATE TABLE {table} (id INTEGER PRIMARY KEY, {columns})')
        c.executemany('INSERT INTO students VALUES (?,?,?,?,?,?,?)', [
            (1,'Aarav Sharma','CSE','86%','82/100','Paid','1'),
            (2,'Priya Verma','CSE','92%','91/100','Pending','1'),
            (3,'Rohan Singh','CSE','78%','75/100','Paid','1')])
        c.execute('INSERT INTO teachers VALUES (?,?,?,?,?)', (1,'Dr. Neha Jain','Python','45000','neha@example.com'))
        c.executemany('INSERT INTO classes VALUES (?,?,?,?,?,?)', [
            (1,'Python Programming','CSE','09:00 AM','B-204','1'),
            (2,'Python Lab','CSE','11:00 AM','Lab 3','1')])
        c.execute('INSERT INTO notices VALUES (?,?,?)',(1,'Semester update','Internal assessments begin next week.'))
        for name, role, person in [('admin','admin',0),('student','student',1),('teacher','teacher',1)]:
            c.execute('INSERT INTO users(username,password,role,person_id,recovery) VALUES (?,?,?,?,?)',
                      (name,generate_password_hash(os.environ['ADMIN_PASSWORD'] if name=='admin' and os.environ.get('RENDER') else secrets.token_urlsafe(24) if os.environ.get('RENDER') else 'demo123'),role,person,''))
def rows(table, condition='', args=()):
    with db() as c:
        return [dict(r) for r in c.execute(f'SELECT * FROM {table} '+condition,args)]
@app.before_request
def verify_session():
    if session.get('username') and not rows('users','WHERE username=? AND role=? AND person_id=?',(session['username'],session['role'],session['person'])): session.clear()
    if request.method == 'POST' and not secrets.compare_digest(session.get('csrf','missing'), request.form.get('csrf','')): abort(403)
    session.setdefault('csrf', secrets.token_hex(24))
@app.route('/', methods=['GET','POST'])
def login():
    error = ''
    if request.method == 'POST':
        users = rows('users','WHERE username=?',(request.form['username'],))
        if users and check_password_hash(users[0]['password'],request.form['password']):
            u = users[0]
            session.clear()
            session.update(role=u['role'], person=u['person_id'], username=u['username'])
            return redirect('/dashboard')
        error = 'Incorrect username or password.'
    return render_template('login.html',error=error)
@app.route('/dashboard')
def dashboard():
    role = session.get('role')
    if not role:
        return redirect('/')
    person = session['person']
    profile = None
    if role == 'admin':
        data = {t: rows(t) for t in FIELDS}
        for u in data['users']:
            u['password'] = u['recovery'] = ''
    elif role == 'student':
        found = rows('students','WHERE id=?',(person,))
        if not found: abort(404)
        profile = found[0]
        data = {'classes': rows('classes','WHERE course=?',(profile['course'],)), 'notices': rows('notices')}
    else:
        found = rows('teachers','WHERE id=?',(person,))
        if not found: abort(404)
        profile = found[0]
        data = {'students': rows('students','WHERE teacher=?',(person,)),
                'classes': rows('classes','WHERE teacher=?',(person,)), 'notices': rows('notices')}
    return render_template('dashboard.html',role=role,profile=profile,data=data,fields=FIELDS)
@app.post('/manage/<table>')
def manage(table):
    if session.get('role') != 'admin' or table not in FIELDS:
        abort(403)
    record = request.form.get('id','')
    action = request.form.get('action')
    fields = FIELDS[table][1:]
    with db() as c:
        if action == 'delete':
            if table == 'users' and c.execute('SELECT username FROM users WHERE id=?',(record,)).fetchone()[0] == session['username']:
                abort(400, 'Cannot delete your own account')
            c.execute(f'DELETE FROM {table} WHERE id=?',(record,))
            if table in ('students','teachers'): c.execute('DELETE FROM users WHERE role=? AND person_id=?',(table[:-1],record))
        else:
            values = [request.form.get(f,'').strip() for f in fields]
            if table == 'users':
                if c.execute('SELECT id FROM users WHERE username=? AND id!=?',(values[0],record or 0)).fetchone(): abort(400,'Username already exists')
                if values[2] not in ('admin','student','teacher'): abort(400)
                if values[1]: values[1] = generate_password_hash(values[1])
                elif record:
                    values[1] = c.execute('SELECT password FROM users WHERE id=?',(record,)).fetchone()[0]
                else: abort(400, 'Password required')
                if values[4]: values[4] = generate_password_hash(values[4])
                elif record: values[4] = c.execute('SELECT recovery FROM users WHERE id=?',(record,)).fetchone()[0]
            if record:
                assignments = ','.join(f'{f}=?' for f in fields)
                c.execute(f'UPDATE {table} SET {assignments} WHERE id=?',values+[record])
            else:
                result = c.execute(f'INSERT INTO {table} ({",".join(fields)}) VALUES ({",".join("?" for f in fields)})',values)
                if table in ('students','teachers'):
                    username, password, recovery = [request.form.get(f,'').strip() for f in ('username','password','recovery')]
                    if not username or len(password)<8 or len(recovery)<12: abort(400,'Username, 8-character password and 12-character recovery code required')
                    if c.execute('SELECT id FROM users WHERE username=?',(username,)).fetchone(): abort(400,'Username already exists')
                    c.execute('INSERT INTO users(username,password,role,person_id,recovery) VALUES (?,?,?,?,?)',(username,generate_password_hash(password),table[:-1],result.lastrowid,generate_password_hash(recovery)))
    return redirect('/dashboard#'+table)
@app.route('/password', methods=['GET','POST'])
def password():
    error = ''
    if request.method == 'POST':
        username = session.get('username') or request.form.get('username','')
        found = rows('users','WHERE username=?',(username,))
        key = 'password' if session.get('username') else 'recovery'
        new = request.form['new_password']
        if found and found[0][key] and check_password_hash(found[0][key],request.form['proof']) and len(new)>=8 and new==request.form['confirm'] and (key=='password' or len(request.form.get('new_recovery',''))>=12):
            with db() as c:
                c.execute('UPDATE users SET password=? WHERE id=?',(generate_password_hash(new),found[0]['id']))
                if key=='recovery': c.execute('UPDATE users SET recovery=? WHERE id=?',(generate_password_hash(request.form['new_recovery']),found[0]['id']))
            session.clear()
            return redirect('/?changed=1')
        error = 'Invalid credentials or passwords do not match (minimum 8 characters).'
    return render_template('password.html',error=error, signed_in=bool(session.get('username')))
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')
setup()
if __name__ == '__main__':
    app.run(debug=False)
