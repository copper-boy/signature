# signature
____
## Установка

- Клонирование репозитория
  + **git clone https://github.com/DededGit/signature**
  + **cd signature**
    - Создание вирутального окружения
      + python -m venv venv
      - Активация 
        - Linux
          + source venv/bin/activate
        - Windows
          + venv\Scripts\activate.bat
    - Установка зависимостей
      + **pip install -r requirements.txt**

## Использование

**python digital_signature.py**<br><br>
**Нужна почта @gmail.com, чтобы с неё можно было отправлять, на ней должны быть отключены
все уровни защиты и разрешен вход с небезопасного устройства, чтобы можно было читать с почты письма
нужно все как в пункте с 'отправлением', но IMAP должен быть включен, можете попробывать
создать новую пустую почту и сделать все как в предыдущих пунктах.**<br>
**Во время работы приложения не рекомендуется удалять письма.**

## Принцип работы
Допустим вы зашифровали сообщение с помощью приватного ключа 
и сказали, что эта ваша подпись.<br>
Теперь вы можете отправлять само сообщение и подпись с публичным ключом, чтобы доказать,
о том что сообщение принадлежит вам.<br><br>
Если злоумышленник получить вашу подпись и публичный ключ, но передаст другое сообщение,
то оно не пройдет проверку, но он может создать и свою подпись, при помощи своего приватного ключа,
которая будет проходит проверку, но не будет принадлежать другому человеку.<br><br>
Таким образом и будут проверяться подписи, если она верна, то она принадлежит владельцу подписи.