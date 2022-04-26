import imaplib
import mimetypes
import os
import shutil
import smtplib
from email import encoders
from email.mime.audio import MIMEAudio
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import cryptography.exceptions
import imap_tools
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QFileDialog, QMessageBox

from ui_mainwindow import Ui_MainWindow


class MainWindow(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self):
        self.mail = imap_tools.MailBox('imap.gmail.com')
        self.is_logged = False
        super(MainWindow, self).__init__()
        self.setupUi(self)

    def on_key_generate_clicked(self):
        text = self.key_name_text.toPlainText()
        if not text or text == 'Ключ':
            return QMessageBox.critical(self, 'Error', 'Invalid key name value')
        if os.path.exists(f'{text}.pem'):
            return QMessageBox.critical(self, 'Error', 'The key already exists, you need to remove it first')
        with open(f'{text}.pem', 'wb') as key_file:
            key_file.write(rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()))
            QMessageBox.information(self, 'Information', 'Key created successfully')

    def on_key_delete_clicked(self):
        current_text = self.keys_combo_box.currentText()
        if current_text == 'Ключ':
            return QMessageBox.critical(self, 'Error', 'The key is the notation')
        if os.path.exists(f'{current_text}.pem'):
            os.remove(f'{current_text}.pem')
        self.keys_combo_box.removeItem(self.keys_combo_box.findText(current_text))

    def on_keys_update_clicked(self):
        self.keys_combo_box.clear()
        self.keys_combo_box.addItems(
            ['Ключ'] + [file.split('.')[0] for file in os.listdir() if os.path.isfile(file) and file.endswith('.pem')])
        QMessageBox.information(self, 'Information', 'Keys list updated')

    def on_send_clicked(self):
        if self.keys_combo_box.currentText() == 'Ключ':
            return QMessageBox.critical(self, 'Error', 'The key is the notation')
        addr_from = self.addr_from_text.toPlainText()
        password = self.password_text.toPlainText()
        addr_to = self.addr_to_text.toPlainText()
        digital_message = self.digital_signature_text.toPlainText()
        try:
            MainWindow.__is_fields_empty([addr_from, password, addr_to, digital_message])  # if okay, no except
        except ValueError as v:
            return QMessageBox.critical(self, 'Error', v.args[0])
        file, check = QFileDialog.getOpenFileName(self, 'Open File', './')
        if check:
            with open(f'{self.keys_combo_box.currentText()}.pem', "rb") as key_file:
                private_key = serialization.load_pem_private_key(key_file.read(), password=None)
                dir_name = 'temp/' + digital_message
                if os.path.exists(dir_name):
                    shutil.rmtree(dir_name)
                os.makedirs(dir_name)
                with open(dir_name + f'/{digital_message}.sig', 'wb') as signature_file, open(
                        dir_name + f'/{digital_message}.asc', 'wb') as public_key:
                    signature_file.write(private_key.sign(bytes(digital_message, 'utf-8'),
                                                          padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                                      salt_length=padding.PSS.MAX_LENGTH),
                                                          hashes.SHA256()))

                    public_key.write(private_key.public_key().public_bytes(encoding=serialization.Encoding.OpenSSH,
                                                                           format=serialization.PublicFormat.OpenSSH))

                files = [file, f'temp/{digital_message}']
                file_name = file.split('/')[len(file.split('/')) - 1]
                try:
                    MainWindow.__send_email(addr_from, password, addr_to,
                                            f'digital signature {file_name}, message:{digital_message}', '', files)
                except smtplib.SMTPAuthenticationError:
                    return QMessageBox.critical(self, 'Error', f'Auth error with email address \'{addr_from}\'')
                except smtplib.SMTPRecipientsRefused:
                    return QMessageBox.critical(self, 'Error', f'Address \'{addr_to}\' invalid email address.')

                QMessageBox.information(self, 'Information', 'Successfully sent')

    def on_check_signature_clicked(self):
        if not self.is_logged:
            return QMessageBox.critical(self, 'Error', 'You need to complete authentication')
        item = self.mails_combo_box.currentText()
        if item == 'Выберите письмо':
            return QMessageBox.critical(self, 'Error', 'The current item is the notation')

        for msg in self.mail.fetch():
            if msg.subject == item:
                signature: bytes
                public_key: rsa.RSAPublicKey
                message = msg.subject.split(',')[1].split(':')[1]
                for attachment in msg.attachments:
                    match attachment.filename.split('.')[1]:
                        case 'sig':
                            try:
                                match len(attachment.payload):
                                    case 0:
                                        raise ValueError('Empty signature')
                                    case _:
                                        signature = bytes(attachment.payload)
                            except ValueError as v:
                                return QMessageBox.critical(self, 'Error', v.args[0])
                        case 'asc':
                            try:
                                public_key = serialization.load_ssh_public_key(attachment.payload)
                            except (Exception, ValueError, TypeError):
                                return QMessageBox.critical(self, 'Error', 'Invalid key format')
                try:
                    public_key.verify(signature,
                                      str.encode(message),
                                      padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                  salt_length=padding.PSS.MAX_LENGTH),
                                      hashes.SHA256())
                except cryptography.exceptions.InvalidSignature:
                    return QMessageBox.critical(self, 'Error', 'Not a valid digital signature')
                except cryptography.exceptions.UnsupportedAlgorithm:
                    return QMessageBox.critical(self, 'Error', 'Unsupported key type algorith, needed openssh')
                except ValueError:
                    return QMessageBox.critical(self, 'Error', 'Invalid line format')
                return QMessageBox.information(self, 'Information', f'Valid digital signature from {msg.from_}')
        return QMessageBox.critical(self, 'Error', 'The current message is not exists, update mails list')

    def on_update_emails_clicked(self):
        self.mails_combo_box.clear()
        self.mails_combo_box.addItem('Выберите письмо')
        match self.is_logged:
            case True:
                self.mails_combo_box.addItems([subject.subject for subject in self.mail.fetch() if
                                               subject.subject.startswith('digital signature')])
                QMessageBox.information(self, 'Information', 'Mails list updated')
            case False:
                QMessageBox.critical(self, 'Error', 'You need to complete authentication')

    def on_save_file_clicked(self):
        if not self.is_logged:
            return QMessageBox.critical(self, 'Error', 'You need to complete authentication')
        item = self.mails_combo_box.currentText()
        if item == 'Выберите письмо':
            return QMessageBox.critical(self, 'Error', 'The current item is the notation')
        for msg in self.mail.fetch():
            if msg.subject == item:
                message = msg.subject.split(',')[0].split(' ')[2]
                for attachment in msg.attachments:
                    if message == attachment.filename:
                        file_type = attachment.filename.split('.')[-1]
                        file, check = QFileDialog.getSaveFileName(self, 'Save file', '', f'All files (*);;.{file_type}')
                        if not check:
                            return QMessageBox.critical(self, 'Error', 'Please select any file')
                        with open(file, 'wb') as download:
                            download.write(attachment.payload)
                        return QMessageBox.information(self, 'Information', 'Successfully downloading file')
        return QMessageBox.critical(self, 'Error', 'The current message is not exists, update mails list')

    def on_auth_clicked(self):
        email = self.address_text.toPlainText()
        password = self.pass_text.toPlainText()
        try:
            MainWindow.__is_fields_empty([email, password])
        except ValueError as v:
            return QMessageBox.critical(self, 'Error', f'{v.args[0]}')

        if self.__email_logout():
            try:
                self.mail = imap_tools.MailBox('imap.gmail.com').login(email, password)
            except imap_tools.errors.MailboxLoginError:
                return QMessageBox.critical(self, 'Error',
                                            'Unsuccessful authentication, it may be the wrong address or password,'
                                            ' or IMAP is disabled in the settings, '
                                            'or insecure applications are allowed')
            except (Exception, imaplib.IMAP4.error):
                return QMessageBox.critical(self, 'Error', 'Can\'t complete authentication')
            self.is_logged = True
            QMessageBox.information(self, 'Information', 'Successfully authentication')

    @staticmethod
    def __is_fields_empty(fields: list[str]):
        if len([i for i in fields if not i]) > 0:
            raise ValueError('Fields can\'t be empty')

    def __email_logout(self):
        if self.is_logged and QMessageBox.question(self, 'Question',
                                                   'Do you wan\'t re-authenticate?') == QMessageBox.Yes:
            self.is_logged = False
        return not self.is_logged

    @staticmethod
    def __send_email(addr_from, password, addr_to, msg_subj, msg_text, files):
        msg = MIMEMultipart()
        msg['From'] = addr_from
        msg['To'] = addr_to
        msg['Subject'] = msg_subj

        body = msg_text
        msg.attach(MIMEText(body, 'plain'))

        MainWindow.__process_attachement(msg, files)
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.ehlo()
        server.starttls()
        server.login(addr_from, password)
        server.send_message(msg)
        server.quit()

    @staticmethod
    def __process_attachement(msg, files):
        for f in files:
            if os.path.isfile(f):
                MainWindow.__attach_file(msg, f)
            elif os.path.exists(f):
                d = os.listdir(f)
                for file in d:
                    MainWindow.__attach_file(msg, f + "/" + file)

    @staticmethod
    def __attach_file(msg, filepath):
        filename = os.path.basename(filepath)
        ctype, encoding = mimetypes.guess_type(filepath)
        if ctype is None or encoding is not None:
            ctype = 'application/octet-stream'
        maintype, subtype = ctype.split('/', 1)
        match maintype:
            case 'text':
                with open(filepath) as fp:
                    file = MIMEText(fp.read(), _subtype=subtype)
            case 'image':
                with open(filepath, 'rb') as fp:
                    file = MIMEImage(fp.read(), _subtype=subtype)
            case 'audio':
                with open(filepath, 'rb') as fp:
                    file = MIMEAudio(fp.read(), _subtype=subtype)
            case _:
                with open(filepath, 'rb') as fp:
                    file = MIMEBase(maintype, subtype)
                    file.set_payload(fp.read())
                    encoders.encode_base64(file)
        file.add_header('Content-Disposition', 'attachment', filename=filename)
        msg.attach(file)


if __name__ == "__main__":
    import sys

    app = QtWidgets.QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()
    sys.exit(app.exec_())
