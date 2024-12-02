import pytest
from app2 import app, db, User, Admin
from werkzeug.security import generate_password_hash

@pytest.fixture(scope='module')
def client():
    # Setup application context and database
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF tokens for testing
    with app.app_context():
        db.create_all()
        user = User(email="testuser@example.com", password=generate_password_hash("password"), is_verified=True)
        admin = Admin(username="superadmin", password=generate_password_hash("superpassword"), role="superadmin")
        db.session.add_all([user, admin])
        db.session.commit()

    yield app.test_client()  # Provide a test client

    # Teardown: drop the database
    with app.app_context():
        db.drop_all()

def test_login(client):
    """Ensure login works correctly."""
    response = client.post('/login', data={'email': 'testuser@example.com', 'password': 'password'}, follow_redirects=True)
    assert b'prediction' in response.data  # or whatever specific output you expect

def test_failed_login(client):
    """Ensure that a wrong login provides the correct error message."""
    response = client.post('/login', data={'email': 'wrong@example.com', 'password': 'wrong'}, follow_redirects=True)
    assert b'login' in response.data

def test_prediction(client):
    """Test the prediction functionality with encoded gender."""
    with client.session_transaction() as sess:
        sess['user'] = 'testuser@example.com'
    
    # Assuming 'Male' is encoded as 0 and 'Female' as 1
    response = client.post('/prediction', data={
        'name': 'John Doe',
        'age': 30,
        'gender': 0,  # Male
        'income_level': 20000,
        'employment_status': 1,
        'education_level': 2,
        'mental_health_status': 0,
        'substance_abuse': 0,
        'family_status': 1,
        'housing_history': 1,
        'disability': 0,
        'region': 1,
        'social_support': 2
    }, follow_redirects=True)
    assert b'Homeless' in response.data or b'Not Homeless' in response.data, "Prediction did not return expected results"
    print("Test successful: test_prediction")



def test_admin_dashboard_access_denied_without_login(client):
    """Test accessing the admin dashboard without logging in redirects to the login page with an unauthorized access message."""
    response = client.get('/admin/dashboard', follow_redirects=True)
    assert b'Admin Login' in response.data  # Checking for the page title in the response
    
   