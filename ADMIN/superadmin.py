from HOMELESSNESS_PREVENTION.ADMIN.app2 import db, Admin
from werkzeug.security import generate_password_hash

# Create the first super admin
superadmin = Admin(
    username='superadmin',
    password=generate_password_hash('superpassword'),  # Replace with a secure password
    role='superadmin'
)

db.session.add(superadmin)
db.session.commit()
