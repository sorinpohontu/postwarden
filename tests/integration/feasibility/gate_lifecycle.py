#!/usr/bin/python3
"""T9: two messages on one port-25 connection with an RSET in between."""
import os
import smtplib

login = os.environ["GATE_LOGIN"]
rcpt = os.environ["GATE_RCPT"]
reject = os.environ["GATE_REJECT_RCPT"]

with smtplib.SMTP("127.0.0.1", 25, timeout=30) as smtp:
    smtp.set_debuglevel(1)
    smtp.ehlo("gate.test")
    print("T9a", smtp.sendmail(login, [rcpt], f"From: {login}\r\nTo: {rcpt}\r\nSubject: gate T9a\r\n\r\nT9a\r\n"))
    smtp.mail(login)
    print("T9 rcpt reject", smtp.rcpt(reject))
    print("T9 rset", smtp.rset())
    print("T9b", smtp.sendmail(login, [rcpt], f"From: {login}\r\nTo: {rcpt}\r\nSubject: gate T9b\r\n\r\nT9b\r\n"))
    smtp.quit()
