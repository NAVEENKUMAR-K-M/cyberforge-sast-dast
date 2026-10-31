"""Order confirmation e-mails."""
import smtplib

from .config import SMTP_HOST


def send(to, body):
    server = smtplib.SMTP_SSL(SMTP_HOST, 465)
    server.login("mailer@pyshop.test", password="M@ilerS3cretPass9")
    server.sendmail("mailer@pyshop.test", to, body)
