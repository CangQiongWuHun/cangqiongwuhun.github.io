#给AI改过了，有些地方是它写的
import sys
from PyQt5.QtCore import pyqtSignal, QObject, QThread, Qt
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QTextEdit, QLineEdit, QPushButton, QLabel, QGridLayout, QComboBox
from PyQt5.QtWebEngineWidgets import QWebEngineView
import pymysql
import bcrypt

class ChatBackend(QObject):
    new_message = pyqtSignal(str, str)
    user_registered = pyqtSignal(str)
    user_logged_in = pyqtSignal(str)
    add_user_success = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        try:
            self.connection = pymysql.connect(host='ip', user='user', password='password', database='database', charset='utf8mb4')
            self.cursor = self.connection.cursor()
            self.create_tables()
            self.registered_users = {}
            self.logged_in_user = None
            self.user_conversations = {}
        except pymysql.Error as e:
            print(f"Database connection error: {e}")

    def create_tables(self):
        try:
            create_users_table_query = """
            CREATE TABLE IF NOT EXISTS users (
                qq_number VARCHAR(20) PRIMARY KEY,
                password VARCHAR(255),
                authentication_info TEXT,
                is_banned BOOLEAN DEFAULT FALSE
            );
            """
            create_conversations_table_query = """
            CREATE TABLE IF NOT EXISTS conversations (
                id INT AUTO_INCREMENT PRIMARY KEY,
                sender VARCHAR(20),
                receiver VARCHAR(20),
                message TEXT
            );
            """
            self.cursor.execute(create_users_table_query)
            self.cursor.execute(create_conversations_table_query)
            self.connection.commit()
        except pymysql.Error as e:
            print(f"Table creation error: {e}")

    def register_user(self, qq_number, password, authentication_info=None):
        try:
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            if qq_number not in self.registered_users:
                insert_user_query = "INSERT INTO users (qq_number, password, authentication_info) VALUES (%s, %s, %s)"
                self.cursor.execute(insert_user_query, (qq_number, hashed_password.decode('utf-8'), authentication_info))
                self.connection.commit()
                self.registered_users[qq_number] = hashed_password
                self.user_registered.emit(qq_number)
                return True
            else:
                return False
        except pymysql.Error as e:
            print(f"User registration error: {e}")
            return False

    def login_user(self, qq_number, password):
        try:
            select_user_query = "SELECT password FROM users WHERE qq_number=%s"
            self.cursor.execute(select_user_query, (qq_number))
            result = self.cursor.fetchone()
            if result:
                hashed_password = result[0].encode('utf-8')
                if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
                    self.logged_in_user = qq_number
                    self.user_logged_in.emit(qq_number)
                    return True
            return False
        except pymysql.Error as e:
            print(f"User login error: {e}")
            return False

    def add_user(self, current_user, new_user):
        try:
            if new_user not in self.user_conversations.get(current_user, []):
                if current_user not in self.user_conversations:
                    self.user_conversations[current_user] = [new_user]
                else:
                    self.user_conversations[current_user].append(new_user)
                self.add_user_success.emit(new_user)
                return True
            else:
                return False
        except Exception as e:
            print(f"Add user error: {e}")
            return False

    def send_message(self, sender, receiver, message):
        try:
            if sender and receiver and message:
                if receiver not in self.user_conversations.get(sender, []):
                    self.add_user(sender, receiver)
                if sender not in self.user_conversations.get(receiver, []):
                    self.add_user(receiver, sender)
                conversation_key = tuple(sorted([sender, receiver]))
                if conversation_key not in self.user_conversations:
                    self.user_conversations[conversation_key] = []
                insert_message_query = "INSERT INTO conversations (sender, receiver, message) VALUES (%s, %s, %s)"
                self.cursor.execute(insert_message_query, (sender, receiver, message))
                self.connection.commit()
                self.user_conversations[conversation_key].append(f"{sender}: {message}")
                self.new_message.emit(sender, f"{sender}: {message}")
        except pymysql.Error as e:
            print(f"Send message error: {e}")

class ChatWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("在线聊天软件")
        self.resize(800, 600)

        layout = QVBoxLayout()

        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        layout.addWidget(self.chat_display)

        self.message_input = QLineEdit()
        layout.addWidget(self.message_input)

        self.send_button = QPushButton("发送")
        self.send_button.clicked.connect(self.send_message)
        layout.addWidget(self.send_button)

        grid_layout = QGridLayout()
        self.qq_label = QLabel("QQ 号：")
        grid_layout.addWidget(self.qq_label, 0, 0)
        self.qq_input = QLineEdit()
        grid_layout.addWidget(self.qq_input, 0, 1)
        self.password_label = QLabel("密码：")
        grid_layout.addWidget(self.password_label, 1, 0)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        grid_layout.addWidget(self.password_input, 1, 1)
        self.login_button = QPushButton("登录")
        self.login_button.clicked.connect(self.login)
        grid_layout.addWidget(self.login_button, 2, 0)
        self.register_button = QPushButton("注册")
        self.register_button.clicked.connect(self.register)
        grid_layout.addWidget(self.register_button, 2, 1)

        self.add_user_label = QLabel("添加用户：")
        grid_layout.addWidget(self.add_user_label, 3, 0)
        self.add_user_input = QLineEdit()
        grid_layout.addWidget(self.add_user_input, 3, 1)
        self.add_user_button = QPushButton("添加")
        self.add_user_button.clicked.connect(self.add_user)
        grid_layout.addWidget(self.add_user_button, 3, 2)

        self.current_user_label = QLabel()
        grid_layout.addWidget(self.current_user_label, 4, 0, 1, 2)

        self.user_list = QComboBox()
        self.user_list.currentIndexChanged.connect(self.change_conversation)
        grid_layout.addWidget(self.user_list, 5, 0, 1, 2)

        layout.addLayout(grid_layout)

        self.setLayout(layout)

        self.backend = ChatBackend()
        self.backend.new_message.connect(self.display_message)
        self.backend.user_registered.connect(self.show_registration_success)
        self.backend.user_logged_in.connect(self.show_login_success)
        self.backend.add_user_success.connect(self.show_add_user_success)

        self.logged_in = False

    def login(self):
        qq_number = self.qq_input.text()
        password = self.password_input.text()
        if self.backend.login_user(qq_number, password):
            self.current_user_label.setText(f"当前用户：{qq_number}")
            self.logged_in = True
            self.populate_user_list(qq_number)
        else:
            self.show_error("登录失败，请检查 QQ 号和密码。")

    def register(self):
        qq_number = self.qq_input.text()
        password = self.password_input.text()
        authentication_info = None  
        if self.backend.register_user(qq_number, password, authentication_info):
            self.show_message("注册成功！")
        else:
            self.show_error("该 QQ 号已注册。")

    def add_user(self):
        if self.logged_in:
            current_user = self.current_user_label.text().split(": ")[1]
            new_user = self.add_user_input.text()
            if self.backend.add_user(current_user, new_user):
                self.show_message(f"成功添加用户 {new_user}。")
                self.populate_user_list(current_user)
            else:
                self.show_error(f"用户 {new_user} 已存在或添加失败。")
        else:
            self.show_error("请先登录。")

    def send_message(self):
        if self.logged_in:
            current_user = self.current_user_label.text().split(": ")[1]
            receiver = self.user_list.currentText()
            message = self.message_input.text()
            if receiver:
                self.backend.send_message(current_user, receiver, message)
                self.message_input.clear()
            else:
                self.show_error("请选择接收消息的用户。")
        else:
            self.show_error("请先登录。")

    def display_message(self, sender, message):
        if self.logged_in:
            current_user = self.current_user_label.text().split(": ")[1]
            conversation_key = tuple(sorted([current_user, sender]))
            if sender == current_user:
                self.chat_display.append(f"你： {message}")
            else:
                self.chat_display.append(message)

    def populate_user_list(self, current_user):
        try:
            self.user_list.clear()
            if current_user in self.backend.user_conversations:
                for user in self.backend.user_conversations[current_user]:
                    self.user_list.addItem(user)
        except Exception as e:
            print(f"Populate user list error: {e}")

    def change_conversation(self):
        if self.logged_in:
            current_user = self.current_user_label.text().split(": ")[1]
            selected_user = self.user_list.currentText()
            try:
                self.chat_display.clear()
                conversation_key = tuple(sorted([current_user, selected_user]))
                if conversation_key in self.backend.user_conversations:
                    for message in self.backend.user_conversations[conversation_key]:
                        self.chat_display.append(message)
            except Exception as e:
                print(f"Change conversation error: {e}")

    def show_registration_success(self, qq_number):
        self.show_message(f"注册成功！QQ 号：{qq_number}")

    def show_login_success(self, qq_number):
        self.show_message(f"登录成功！欢迎 {qq_number}。")

    def show_add_user_success(self, user):
        self.show_message(f"成功添加用户 {user}。")

    def show_error(self, message):
        self.show_message(message, error=True)

    def show_message(self, message, error=False):
        if error:
            self.chat_display.append(f"错误：{message}")
        else:
            self.chat_display.append(message)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    chat_window = ChatWindow()
    chat_window.show()
    sys.exit(app.exec())  # 使用 app.exec() 而不是 app.exec_()，确保程序不会意外退出
