from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, FileField
from wtforms.validators import DataRequired
from werkzeug.utils import secure_filename
from flask_migrate import Migrate
import os

# 初始化 Flask 应用
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'  # 设置 Flask 的密钥，用于 session 加密等
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'  # 配置数据库地址
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # 关闭对象修改追踪，提高性能
app.config['UPLOAD_FOLDER'] = 'uploaded_files'  # 上传文件保存路径
app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'docx', 'pptx', 'xlsx', 'txt'}  # 允许上传的文件类型

# 创建上传目录（如果不存在）
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# 初始化数据库及迁移功能
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# 用户模型
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)  # 标记是否为管理员

    def __init__(self, username, password, is_admin=False):
        self.username = username
        self.password = password
        self.is_admin = is_admin

# 公告模型
class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)  # 自动添加时间戳

# 资源资料模型
class Resource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)  # 文件路径
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    uploader = db.relationship('User', backref=db.backref('resources', lazy=True))

# 班级模型
class Classroom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

# 学生与班级关系模型
class StudentClass(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    class_id = db.Column(db.Integer, db.ForeignKey('classroom.id'), nullable=False)
    student = db.relationship('User', backref=db.backref('student_class', uselist=False))
    classroom = db.relationship('Classroom')

# 课程表模型
class Timetable(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    class_id = db.Column(db.Integer, db.ForeignKey('classroom.id'), nullable=False)
    weekday = db.Column(db.String(10), nullable=False)
    start_time = db.Column(db.Time, nullable=False)
    end_time = db.Column(db.Time, nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    classroom = db.relationship('Classroom', backref=db.backref('timetables', lazy=True))

# 上传资源的表单类
class ResourceUploadForm(FlaskForm):
    title = StringField('标题', validators=[DataRequired()])
    category = SelectField('类别', choices=[('Teaching Materials', '教学资料'), ('Research Paper', '研究论文')], validators=[DataRequired()])
    file = FileField('上传文件', validators=[DataRequired()])

# 初始化默认用户和班级数据
with app.app_context():
    db.create_all()
    brooks = User.query.filter_by(username='Brooks').first()
    if not brooks:
        brooks = User(username='Brooks', password=generate_password_hash('password123', method='pbkdf2:sha256'), is_admin=True)
        db.session.add(brooks)
        db.session.commit()
    if Classroom.query.count() == 0:
        db.session.add_all([
            Classroom(name='G10 TSL'),
            Classroom(name='10B'),
            Classroom(name='11A')
        ])
        db.session.commit()

# 首页路由
@app.route('/')
def home():
    announcements = Announcement.query.order_by(Announcement.timestamp.desc()).limit(5).all()
    return render_template('home.html')
    
#语言切换路由
@app.route('/set_language/<lang_code>')
def set_language(lang_code):
    session['lang'] = lang_code
    return redirect(url_for('home'))

# 登录功能
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('dashboard'))
        else:
            return "登录失败，请检查用户名和密码", 401
    return render_template('login.html')

# 注册功能
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

# 用户面板（显示公告、课程表）
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    student_class = StudentClass.query.filter_by(user_id=user.id).first()
    if not student_class and not user.is_admin:
        return redirect(url_for('select_class'))

    announcements = Announcement.query.order_by(Announcement.timestamp.desc()).all()
    schedule, current_class, next_class = [], None, None
    if not user.is_admin:
        schedule, current_class, next_class = get_today_schedule_and_progress(student_class.class_id)

    return render_template(
        'dashboard.html',
        user=user,
        announcements=announcements,
        today_schedule=schedule,
        current_class=current_class,
        next_class=next_class
    )

# 获取当天的课程安排以及当前和下一节课

def get_today_schedule_and_progress(class_id):
    today_weekday = datetime.now().strftime('%A')  # 获取今天是星期几
    now = datetime.now().time()  # 当前时间
    schedule = Timetable.query.filter_by(class_id=class_id, weekday=today_weekday).order_by(Timetable.start_time).all()
    current = None
    next_class = None
    for entry in schedule:
        if entry.start_time <= now <= entry.end_time:
            current = entry
        elif now < entry.start_time and not next_class:
            next_class = entry
    return schedule, current, next_class

# 公告发布页面
@app.route('/announce', methods=['GET', 'POST'])
def announce():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        new_announcement = Announcement(title=title, content=content)
        db.session.add(new_announcement)
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('announce.html')

# 上传资源页面
@app.route('/upload_resource', methods=['GET', 'POST'])
def upload_resource():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not user.is_admin:
        return "权限不足，无法上传资料", 403
    form = ResourceUploadForm()
    if form.validate_on_submit():
        file = form.file.data
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            new_resource = Resource(
                title=form.title.data,
                category=form.category.data,
                file_path=filename,
                uploaded_by=user.id
            )
            db.session.add(new_resource)
            db.session.commit()
            flash('资料上传成功！', 'success')
            return redirect(url_for('dashboard'))
    return render_template('upload_resource.html', form=form)

# 资源浏览页面
@app.route('/resources', methods=['GET'])
def resources():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    keyword = request.args.get('keyword', '').strip()
    category = request.args.get('category', '')

    query = Resource.query
    if keyword:
        query = query.filter(Resource.title.ilike(f'%{keyword}%'))  # 关键字模糊搜索
    if category and category != 'all':
        query = query.filter_by(category=category)

    resources = query.order_by(Resource.upload_date.desc()).all()
    return render_template('resources.html', resources=resources, keyword=keyword, category=category)

# 提供上传文件的访问
@app.route('/uploads/<filename>')
def get_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# 学生选择班级页面
@app.route('/select_class', methods=['GET', 'POST'])
def select_class():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    existing = StudentClass.query.filter_by(user_id=user_id).first()
    if existing:
        return redirect(url_for('dashboard'))
    classrooms = Classroom.query.all()
    if request.method == 'POST':
        selected_class = request.form.get('class_id')
        if selected_class:
            student_class = StudentClass(user_id=user_id, class_id=int(selected_class))
            db.session.add(student_class)
            db.session.commit()
            return redirect(url_for('dashboard'))
    return render_template('select_class.html', classrooms=classrooms)

# 管理员查看课程表页面
@app.route('/admin/timetable', methods=['GET', 'POST'])
def manage_timetable():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not user.is_admin:
        return "权限不足，仅管理员可访问", 403
    classrooms = Classroom.query.all()
    selected_class_id = request.form.get('class_id') if request.method == 'POST' else None
    timetable = []
    if selected_class_id:
        timetable = Timetable.query.filter_by(class_id=selected_class_id).order_by(Timetable.weekday, Timetable.start_time).all()
    return render_template('admin_timetable.html', classrooms=classrooms, timetable=timetable, selected_class_id=selected_class_id)

# 添加课程表条目（管理员）
@app.route('/admin/timetable/add', methods=['POST'])
def add_timetable_entry():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not user.is_admin:
        return "权限不足", 403
    class_id = request.form['class_id']
    weekday = request.form['weekday']
    start_time = request.form['start_time']
    end_time = request.form['end_time']
    subject = request.form['subject']
    new_entry = Timetable(
        class_id=class_id,
        weekday=weekday,
        start_time=datetime.strptime(start_time, '%H:%M').time(),
        end_time=datetime.strptime(end_time, '%H:%M').time(),
        subject=subject
    )
    db.session.add(new_entry)
    db.session.commit()
    return redirect(url_for('manage_timetable'))

# 检查文件类型是否合法

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# 启动应用
if __name__ == '__main__':
    app.run(debug=True)