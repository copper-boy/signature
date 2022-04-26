from PyQt5 import QtWidgets
from PyQt5.QtCore import QCoreApplication, QMetaObject, QRect, QSize, Qt
from PyQt5.QtWidgets import (QComboBox, QFileDialog, QGridLayout, QLabel,
                             QMenuBar, QMessageBox, QPushButton, QSplitter,
                             QStatusBar, QTabWidget, QTextEdit, QWidget)


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
