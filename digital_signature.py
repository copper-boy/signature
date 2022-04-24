import imaplib
import mimetypes

import cryptography.exceptions
import imap_tools
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import QRect, Qt, QMetaObject, QCoreApplication, QSize
from PyQt5.QtWidgets import (QFileDialog, QGridLayout, QPushButton, QWidget, QTabWidget, QSplitter, QTextEdit, QMenuBar,
                             QLabel, QComboBox, QMessageBox, QStatusBar)

import shutil

import os
import smtplib
from email import encoders  # Импортируем энкодер
from email.mime.base import MIMEBase  # Общий тип
from email.mime.text import MIMEText  # Текст/HTML
from email.mime.image import MIMEImage  # Изображения
from email.mime.audio import MIMEAudio  # Аудио
from email.mime.multipart import MIMEMultipart  # Многокомпонентный объект

from imap_tools import MailBox, AND
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


'''AUTO GEN CLASS'''
class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        if not MainWindow.objectName():
            MainWindow.setObjectName(u"MainWindow")
        MainWindow.resize(750, 281)
        MainWindow.setMaximumSize(QSize(750, 281))
        MainWindow.setContextMenuPolicy(Qt.NoContextMenu)
        self.centralwidget = QWidget(MainWindow)
        self.centralwidget.setObjectName(u"centralwidget")
        self.tab = QTabWidget(self.centralwidget)
        self.tab.setObjectName(u"tab")
        self.tab.setGeometry(QRect(0, 0, 750, 260))
        self.send = QWidget()
        self.send.setObjectName(u"send")
        self.widget = QWidget(self.send)
        self.widget.setObjectName(u"widget")
        self.widget.setGeometry(QRect(0, 0, 731, 221))
        self.send_grid_layout = QGridLayout(self.widget)
        self.send_grid_layout.setObjectName(u"send_grid_layout")
        self.send_grid_layout.setContentsMargins(0, 0, 0, 0)
        self.addr_from_text = QTextEdit(self.widget)
        self.addr_from_text.setObjectName(u"addr_from_text")

        self.send_grid_layout.addWidget(self.addr_from_text, 6, 0, 1, 1)

        self.addr_from_label = QLabel(self.widget)
        self.addr_from_label.setObjectName(u"addr_from_label")

        self.send_grid_layout.addWidget(self.addr_from_label, 5, 0, 1, 1)

        self.addr_to_label = QLabel(self.widget)
        self.addr_to_label.setObjectName(u"addr_to_label")

        self.send_grid_layout.addWidget(self.addr_to_label, 5, 2, 1, 1)

        self.key_name_label = QLabel(self.widget)
        self.key_name_label.setObjectName(u"key_name_label")

        self.send_grid_layout.addWidget(self.key_name_label, 2, 0, 1, 1)

        self.delete_key_button = QPushButton(self.widget)
        self.delete_key_button.setObjectName(u"delete_key_button")

        self.send_grid_layout.addWidget(self.delete_key_button, 2, 3, 1, 1)

        self.keys_combo_box = QComboBox(self.widget)
        self.keys_combo_box.addItem("")
        self.keys_combo_box.setObjectName(u"keys_combo_box")

        self.send_grid_layout.addWidget(self.keys_combo_box, 3, 3, 1, 1)

        self.send_button = QPushButton(self.widget)
        self.send_button.setObjectName(u"send_button")

        self.send_grid_layout.addWidget(self.send_button, 6, 3, 1, 1)

        self.password = QLabel(self.widget)
        self.password.setObjectName(u"password")

        self.send_grid_layout.addWidget(self.password, 5, 1, 1, 1)

        self.digital_signature_text = QTextEdit(self.widget)
        self.digital_signature_text.setObjectName(u"digital_signature_text")

        self.send_grid_layout.addWidget(self.digital_signature_text, 1, 0, 1, 3)

        self.update_keys_button = QPushButton(self.widget)
        self.update_keys_button.setObjectName(u"update_keys_button")

        self.send_grid_layout.addWidget(self.update_keys_button, 4, 3, 1, 1)

        self.password_text = QTextEdit(self.widget)
        self.password_text.setObjectName(u"password_text")

        self.send_grid_layout.addWidget(self.password_text, 6, 1, 1, 1)

        self.addr_to_text = QTextEdit(self.widget)
        self.addr_to_text.setObjectName(u"addr_to_text")

        self.send_grid_layout.addWidget(self.addr_to_text, 6, 2, 1, 1)

        self.digital_signature_label = QLabel(self.widget)
        self.digital_signature_label.setObjectName(u"digital_signature_label")

        self.send_grid_layout.addWidget(self.digital_signature_label, 0, 0, 1, 1)

        self.key_name_text = QTextEdit(self.widget)
        self.key_name_text.setObjectName(u"key_name_text")

        self.send_grid_layout.addWidget(self.key_name_text, 3, 0, 1, 2)

        self.generate_key_button = QPushButton(self.widget)
        self.generate_key_button.setObjectName(u"generate_key_button")

        self.send_grid_layout.addWidget(self.generate_key_button, 3, 2, 1, 1)

        self.tab.addTab(self.send, "")
        self.receive = QWidget()
        self.receive.setObjectName(u"receive")
        self.widget1 = QWidget(self.receive)
        self.widget1.setObjectName(u"widget1")
        self.widget1.setGeometry(QRect(0, 110, 731, 101))
        self.receive_grid_layout = QGridLayout(self.widget1)
        self.receive_grid_layout.setObjectName(u"receive_grid_layout")
        self.receive_grid_layout.setContentsMargins(0, 0, 0, 0)
        self.mails_combo_box = QComboBox(self.widget1)
        self.mails_combo_box.addItem("")
        self.mails_combo_box.setObjectName(u"mails_combo_box")

        self.receive_grid_layout.addWidget(self.mails_combo_box, 0, 1, 1, 1)

        self.update_mails_list_button = QPushButton(self.widget1)
        self.update_mails_list_button.setObjectName(u"update_mails_list_button")

        self.receive_grid_layout.addWidget(self.update_mails_list_button, 0, 2, 1, 1)

        self.password_label = QLabel(self.widget1)
        self.password_label.setObjectName(u"password_label")

        self.receive_grid_layout.addWidget(self.password_label, 1, 1, 1, 1)

        self.auth_button = QPushButton(self.widget1)
        self.auth_button.setObjectName(u"auth_button")

        self.receive_grid_layout.addWidget(self.auth_button, 2, 2, 1, 1)

        self.address_label = QLabel(self.widget1)
        self.address_label.setObjectName(u"address_label")

        self.receive_grid_layout.addWidget(self.address_label, 1, 0, 1, 1)

        self.save_file_button = QPushButton(self.widget1)
        self.save_file_button.setObjectName(u"save_file_button")

        self.receive_grid_layout.addWidget(self.save_file_button, 1, 2, 1, 1)

        self.address_text = QTextEdit(self.widget1)
        self.address_text.setObjectName(u"address_text")

        self.receive_grid_layout.addWidget(self.address_text, 2, 0, 1, 1)

        self.pass_text = QTextEdit(self.widget1)
        self.pass_text.setObjectName(u"pass_text")

        self.receive_grid_layout.addWidget(self.pass_text, 2, 1, 1, 1)

        self.check_digital_signature_button = QPushButton(self.widget1)
        self.check_digital_signature_button.setObjectName(u"check_digital_signature_button")

        self.receive_grid_layout.addWidget(self.check_digital_signature_button, 0, 0, 1, 1)

        self.tab.addTab(self.receive, "")
        MainWindow.setCentralWidget(self.centralwidget)
        self.statusbar = QStatusBar(MainWindow)
        self.statusbar.setObjectName(u"statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        self.generate_key_button.clicked.connect(MainWindow.on_key_generate_clicked)
        self.delete_key_button.clicked.connect(MainWindow.on_key_delete_clicked)
        self.update_keys_button.clicked.connect(MainWindow.on_keys_update_clicked)
        self.send_button.clicked.connect(MainWindow.on_send_clicked)
        self.check_digital_signature_button.clicked.connect(MainWindow.on_check_signature_clicked)
        self.update_mails_list_button.clicked.connect(MainWindow.on_update_emails_clicked)
        self.save_file_button.clicked.connect(MainWindow.on_save_file_clicked)
        self.auth_button.clicked.connect(MainWindow.on_auth_clicked)

        self.tab.setCurrentIndex(0)

        QMetaObject.connectSlotsByName(MainWindow)

    # setupUi

    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(QCoreApplication.translate("MainWindow", u"MainWindow", None))
        self.addr_from_label.setText(QCoreApplication.translate("MainWindow", u"\u0410\u0434\u0440\u0435\u0441", None))
        self.addr_to_label.setText(
            QCoreApplication.translate("MainWindow", u"\u0410\u0434\u0440\u0435\u0441\u0430\u043d\u0442", None))
        self.key_name_label.setText(
            QCoreApplication.translate("MainWindow", u"\u0418\u043c\u044f \u043a\u043b\u044e\u0447\u0430", None))
        self.delete_key_button.setText(QCoreApplication.translate("MainWindow",
                                                                  u"\u0423\u0434\u0430\u043b\u0438\u0442\u044c \u043a\u043b\u044e\u0447",
                                                                  None))
        self.keys_combo_box.setItemText(0, QCoreApplication.translate("MainWindow", u"\u041a\u043b\u044e\u0447", None))

        self.send_button.setText(
            QCoreApplication.translate("MainWindow", u"\u041e\u0442\u043f\u0440\u0430\u0432\u0438\u0442\u044c", None))
        self.password.setText(QCoreApplication.translate("MainWindow", u"\u041f\u0430\u0440\u043e\u043b\u044c", None))
        self.update_keys_button.setText(QCoreApplication.translate("MainWindow",
                                                                   u"\u041e\u0431\u043d\u043e\u0432\u0438\u0442\u044c \u0441\u043f\u0438\u0441\u043e\u043a \u043a\u043b\u044e\u0447\u0435\u0439",
                                                                   None))
        self.digital_signature_label.setText(QCoreApplication.translate("MainWindow",
                                                                        u"\u0421\u043e\u043e\u0431\u0449\u0435\u043d\u0438\u0435 \u0432 \u042d\u0426\u041f",
                                                                        None))
        self.generate_key_button.setText(QCoreApplication.translate("MainWindow",
                                                                    u"\u0421\u0433\u0435\u043d\u0438\u0440\u0438\u0440\u043e\u0432\u0430\u0442\u044c \u043a\u043b\u044e\u0447",
                                                                    None))
        self.tab.setTabText(self.tab.indexOf(self.send), QCoreApplication.translate("MainWindow",
                                                                                    u"\u041e\u0442\u043f\u0440\u0430\u0432\u0438\u0442\u044c",
                                                                                    None))
        self.mails_combo_box.setItemText(0, QCoreApplication.translate("MainWindow",
                                                                      u"\u0412\u044b\u0431\u0435\u0440\u0438\u0442\u0435 \u043f\u0438\u0441\u044c\u043c\u043e",
                                                                      None))

        self.update_mails_list_button.setText(QCoreApplication.translate("MainWindow",
                                                                         u"\u041e\u0431\u043d\u043e\u0432\u0438\u0442\u044c \u0441\u043f\u0438\u0441\u043e\u043a \u043f\u0438\u0441\u0435\u043c",
                                                                         None))
        self.password_label.setText(
            QCoreApplication.translate("MainWindow", u"\u041f\u0430\u0440\u043e\u043b\u044c", None))
        self.auth_button.setText(QCoreApplication.translate("MainWindow",
                                                            u"\u0410\u0432\u0442\u043e\u0440\u0438\u0437\u0438\u0440\u043e\u0432\u0430\u0442\u044c\u0441\u044f",
                                                            None))
        self.address_label.setText(
            QCoreApplication.translate("MainWindow", u"\u0410\u0434\u0440\u0435\u0441", None))
        self.save_file_button.setText(QCoreApplication.translate("MainWindow",
                                                                 u"\u0421\u043e\u0445\u0440\u0430\u043d\u0438\u0442\u044c \u0444\u0430\u0439\u043b",
                                                                 None))
        self.check_digital_signature_button.setText(QCoreApplication.translate("MainWindow",
                                                                               u"\u041f\u0440\u043e\u0432\u0435\u0440\u0438\u0442\u044c \u042d\u0426\u041f",
                                                                               None))
        self.tab.setTabText(self.tab.indexOf(self.receive), QCoreApplication.translate("MainWindow",
                                                                                       u"\u041f\u043e\u043b\u0443\u0447\u0438\u0442\u044c",
                                                                                       None))
    # retranslateUi
'''AUTO GEN CLASS'''



class MainWindow(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self):
        self.mail = imap_tools.MailBox('imap.gmail.com')
        self.is_logged = False
        super(MainWindow, self).__init__()
        self.setupUi(self)

    def on_key_generate_clicked(self):
        text = self.key_name_text.toPlainText()
        if not len(text) or text == 'Ключ':
            return QMessageBox.critical(self, 'Error', 'Invalid key name value')
        if not os.path.exists(f'{text}.pem'):
            with open(f'{text}.pem', 'wb') as key_file:
                key_file.write(rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()))
            QMessageBox.information(self, 'Information', 'Key created successfully')
        else:
            QMessageBox.critical(self, 'Error', 'The key already exists, you need to remove it first')

    def on_key_delete_clicked(self):
        current_text = self.keys_combo_box.currentText()
        if current_text != 'Ключ':
            if os.path.exists(f'{current_text}.pem'):
                os.remove(f'{current_text}.pem')
            self.keys_combo_box.removeItem(self.keys_combo_box.findText(current_text))
        else:
            QMessageBox.critical(self, 'Error', 'The key is the notation')

    def on_keys_update_clicked(self):
        self.keys_combo_box.clear()
        self.keys_combo_box.addItems(
            ['Ключ'] + [file.split('.')[0] for file in os.listdir() if os.path.isfile(file) and file.endswith('.pem')])

    def on_send_clicked(self):
        try:
            addr_from = self.addr_from_text.toPlainText()
            password = self.password_text.toPlainText()
            addr_to = self.addr_to_text.toPlainText()
            digital_message = self.digital_signature_text.toPlainText()
            if len(addr_from) and len(password) and len(
                    addr_to) and self.keys_combo_box.currentText() != 'Ключ' and len(digital_message):
                file, _ = QFileDialog.getOpenFileName(self, 'Open File', './')
                if file and len(digital_message):
                    with open(f'{self.keys_combo_box.currentText()}.pem', "rb") as key_file:
                        private_key = serialization.load_pem_private_key(key_file.read(), password=None)
                        dir_name = 'temp/' + digital_message
                        if os.path.exists(dir_name):
                            if QMessageBox.question(self, 'Question',
                                                    f'The directory {dir_name} is already exists, do you want delete this dir?') == \
                                    QMessageBox.Yes:
                                shutil.rmtree(dir_name)
                        os.makedirs(dir_name)
                        with open(dir_name + f'/{digital_message}.sig', 'wb') as signature_file, open(
                                dir_name + f'/{digital_message}.asc', 'wb') as public_key:
                            signature_file.write(private_key.sign(bytes(digital_message, 'utf-8'),
                                                                  padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                                              salt_length=padding.PSS.MAX_LENGTH),
                                                                  hashes.SHA256()))

                            public_key.write(
                                private_key.public_key().public_bytes(encoding=serialization.Encoding.OpenSSH,
                                                                      format=serialization.PublicFormat.OpenSSH))

                    files = [file, f'temp/{digital_message}']
                    file_name = file.split('/')[len(file.split('/')) - 1]
                    self.__send_email(addr_from, password, addr_to,
                                      f'digital signature {file_name}, message:{digital_message}', '', files)
                    QMessageBox.information(self, 'Information', 'Successfully sent')
            else:
                if self.keys_combo_box.currentText() == 'Ключ':
                    QMessageBox.critical(self, 'Error', 'Select key')
                else:
                    QMessageBox.critical(self, 'Error',
                                         'Fields(address from, password, address to, message) cann\'t be empty')
        except smtplib.SMTPAuthenticationError:
            QMessageBox.critical(self, 'Error', f'Auth error with email address \'{addr_from}\'')
        except smtplib.SMTPRecipientsRefused:
            QMessageBox.critical(self, 'Error', f'Address \'{addr_to}\' invalid email address.')
        if os.path.exists(f'temp/{digital_message}'):
            shutil.rmtree(f'temp/{digital_message}')

    def on_check_signature_clicked(self):
        if not self.is_logged:
            return QMessageBox.critical(self, 'Error', 'You need to complete authentication')
        item = self.mails_combo_box.currentText()
        if item != 'Выберите письмо':
            for msg in self.mail.fetch():
                if msg.subject == item:
                    try:
                        signature: bytes
                        public_key: rsa.RSAPublicKey
                        message = msg.subject.split(',')[1].split(':')[1]
                        for attachment in msg.attachments:
                            if f'{message}.sig' == attachment.filename:
                                signature = bytes(attachment.payload)
                            elif f'{message}.asc' == attachment.filename:
                                public_key = serialization.load_ssh_public_key(attachment.payload)
                        public_key.verify(signature,
                                          str.encode(message),
                                          padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                      salt_length=padding.PSS.MAX_LENGTH),
                                          hashes.SHA256())
                        return QMessageBox.information(self, 'Information', f'Valid digital signature from {msg.from_}')
                    except cryptography.exceptions.InvalidSignature:
                        return QMessageBox.critical(self, 'Error', 'Not a valid digital signature')
                    except cryptography.exceptions.UnsupportedAlgorithm:
                        return QMessageBox.critical(self, 'Error', 'Unsupported key type algorith, needed openssh')

            return QMessageBox.critical(self, 'Error', 'The current message is not exists, update mails list')
        else:
            return QMessageBox.critical(self, 'Error', 'The current item is the notation')

    def on_update_emails_clicked(self):
        self.mails_combo_box.clear()
        self.mails_combo_box.addItem('Выберите письмо')
        if self.is_logged:
            self.mails_combo_box.addItems(
                [subject.subject for subject in self.mail.fetch() if subject.subject.startswith('digital signature')])
            QMessageBox.information(self, 'Information', 'Mails list updated')
        else:
            QMessageBox.critical(self, 'Error', 'You need to complete authentication')

    def on_save_file_clicked(self):
        if not self.is_logged:
            return QMessageBox.critical(self, 'Error', 'You need to complete authentication')
        item = self.mails_combo_box.currentText()
        if item != 'Выберите письмо':
            for msg in self.mail.fetch():
                if msg.subject == item:
                    message = msg.subject.split(',')[0].split(' ')[2]
                    for attachment in msg.attachments:
                        if message == attachment.filename:
                            file_type = attachment.filename.split('.')[len(attachment.filename.split('.')) - 1]
                            file, check = QFileDialog.getSaveFileName(self, f'Save file', '', f'All files (*);;'
                                                                                              f'.{file_type}')
                            if check:
                                with open(file, 'wb') as download:
                                    download.write(attachment.payload)
                            return QMessageBox.information(self, 'Information', f'Successfully downloading file')
            QMessageBox.critical(self, 'Error', 'The current message is not exists, update mails list')
        else:
            QMessageBox.critical(self, 'Error', 'The current item is the notation')

    def on_auth_clicked(self):
        try:
            email = self.address_text.toPlainText()
            password = self.pass_text.toPlainText()
            if self.is_logged:
                if QMessageBox.question(self, 'Question', 'Do you wan\'t re-authenticate?') == QMessageBox.Yes:
                    self.is_logged = False
                    self.mail = imap_tools.MailBox('imap.gmail.com').login(email, password)
                    QMessageBox.information(self, 'Information', 'Successfully authentication')
            else:
                self.mail.login(email, password)
                self.is_logged = True
                QMessageBox.information(self, 'Information', 'Successfully authentication')
        except imap_tools.errors.MailboxLoginError:
            QMessageBox.critical(self, 'Error', 'Unsuccessful authentication, it may be the wrong address or password,'
                                                ' or IMAP is disabled in the settings, '
                                                'or insecure applications are allowed')
        except imaplib.IMAP4.error:
            QMessageBox.critical(self, 'Error', 'Can\'t complete authentication')

    def __send_email(self, addr_from, password, addr_to, msg_subj, msg_text, files):
        msg = MIMEMultipart()  # Создаем сообщение
        msg['From'] = addr_from  # Адресат
        msg['To'] = addr_to  # Получатель
        msg['Subject'] = msg_subj  # Тема сообщения

        body = msg_text
        msg.attach(MIMEText(body, 'plain'))

        self.__process_attachement(msg, files)
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.ehlo()
        server.starttls()
        server.login(addr_from, password)
        server.send_message(msg)
        server.quit()

    def __process_attachement(self, msg, files):  # Функция по обработке списка, добавляемых к сообщению файлов
        for f in files:
            if os.path.isfile(f):
                self.__attach_file(msg, f)
            elif os.path.exists(f):
                dir = os.listdir(f)
                for file in dir:
                    self.__attach_file(msg, f + "/" + file)

    def __attach_file(self, msg, filepath):
        filename = os.path.basename(filepath)
        ctype, encoding = mimetypes.guess_type(filepath)
        if ctype is None or encoding is not None:
            ctype = 'application/octet-stream'
        maintype, subtype = ctype.split('/', 1)
        if maintype == 'text':  # Если текстовый файл
            with open(filepath) as fp:  # Открываем файл для чтения
                file = MIMEText(fp.read(), _subtype=subtype)  # Используем тип MIMEText
                fp.close()  # После использования файл обязательно нужно закрыть
        elif maintype == 'image':  # Если изображение
            with open(filepath, 'rb') as fp:
                file = MIMEImage(fp.read(), _subtype=subtype)
                fp.close()
        elif maintype == 'audio':  # Если аудио
            with open(filepath, 'rb') as fp:
                file = MIMEAudio(fp.read(), _subtype=subtype)
                fp.close()
        else:  # Неизвестный тип файла
            with open(filepath, 'rb') as fp:
                file = MIMEBase(maintype, subtype)  # Используем общий MIME-тип
                file.set_payload(fp.read())  # Добавляем содержимое общего типа (полезную нагрузку)
                fp.close()
                encoders.encode_base64(file)  # Содержимое должно кодироваться как Base64
        file.add_header('Content-Disposition', 'attachment', filename=filename)  # Добавляем заголовки
        msg.attach(file)  # Присоединяем файл к сообщению


if __name__ == "__main__":
    import sys

    app = QtWidgets.QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()
    sys.exit(app.exec_())
