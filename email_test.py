import smtplib
from email.message import EmailMessage
from logger_setup import file_logger, app_logger

# Configuration
smtp_server = "smtp.gmail.com"
smtp_port = 587
email_sender = "arthur.merienne57@gmail.com"
email_password = "vtbz wlqi wmte rnet"  # Remplace ici par le mot de passe d'application
email_receiver = "arthur.merienne57@gmail.com"

# Création du mail
msg = EmailMessage()
msg["Subject"] = "Sujet de l'e-mail"
msg["From"] = email_sender
msg["To"] = email_receiver
msg.set_content("Ceci est un message envoyé depuis Python !")

# Envoi du mail
try:
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(email_sender, email_password)
        server.send_message(msg)
    print("E-mail envoyé avec succès ! ✅")
    app_logger.info("E-mail envoyé avec succès !")
except Exception as e:
    print(f"Erreur lors de l'envoi : {e}")
