from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)

# Configuration
app.secret_key = 'your_secret_key_here'
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'root123'
app.config['MYSQL_DB'] = 'eventify'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql = MySQL(app)

@app.route('/')
def index():
    if 'loggedin' in session:
        if session['role'] == 'organizer':
            return redirect('/organizer/dashboard')
        else:
            return redirect('/provider/dashboard')
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST' and 'email' in request.form and 'password' in request.form:
        email = request.form['email']
        password = request.form['password']
        
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        account = cursor.fetchone()
        
        if account and check_password_hash(account['password'], password):
            session['loggedin'] = True
            session['user_id'] = account['user_id']
            session['name'] = account['name']
            session['email'] = account['email']
            session['role'] = account['role']
            
            if account['role'] == 'organizer':
                return redirect('/organizer/dashboard')
            else:
                return redirect('/provider/dashboard')
        else:
            flash('Incorrect email/password!', 'danger')
    
    return render_template('auth/login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        phone = request.form['phone']
        
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        account = cursor.fetchone()
        
        if account:
            flash('Account already exists!', 'danger')
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            flash('Invalid email address!', 'danger')
        elif not name or not password or not email:
            flash('Please fill out the form!', 'danger')
        else:
            hashed_password = generate_password_hash(password)
            cursor.execute('INSERT INTO users (name, email, password, role, phone) VALUES (%s, %s, %s, %s, %s)',
                         (name, email, hashed_password, role, phone))
            mysql.connection.commit()
            flash('You have successfully registered!', 'success')
            return redirect('/login')
    
    return render_template('auth/register.html')

@app.route('/organizer/dashboard')
def organizer_dashboard():
    if 'loggedin' not in session or session['role'] != 'organizer':
        return redirect('/login')
    
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    # Get organizer's events
    cursor.execute('SELECT * FROM events WHERE organizer_id = %s ORDER BY event_date', (session['user_id'],))
    events = cursor.fetchall()
    
    # Get available services
    cursor.execute('SELECT s.*, u.name as provider_name FROM services s JOIN users u ON s.provider_id = u.user_id WHERE s.availability = "available"')
    services = cursor.fetchall()
    
    return render_template('organizer/dashboard.html', events=events, services=services)

@app.route('/organizer/create_event', methods=['GET', 'POST'])
def create_event():
    if 'loggedin' not in session or session['role'] != 'organizer':
        return redirect('/login')
    
    if request.method == 'POST':
        event_name = request.form['event_name']
        event_date = request.form['event_date']
        location = request.form['location']
        budget = request.form['budget']
        description = request.form['description']
        
        cursor = mysql.connection.cursor()
        cursor.execute('INSERT INTO events (organizer_id, event_name, event_date, location, budget, description) VALUES (%s, %s, %s, %s, %s, %s)',
                     (session['user_id'], event_name, event_date, location, budget, description))
        mysql.connection.commit()
        flash('Event created successfully!', 'success')
        return redirect('/organizer/dashboard')
    
    return render_template('organizer/create_event.html')

@app.route('/organizer/book_service/<int:service_id>', methods=['POST'])
def book_service(service_id):
    if 'loggedin' not in session or session['role'] != 'organizer':
        return redirect('/login')
    
    event_id = request.form['event_id']
    
    cursor = mysql.connection.cursor()
    cursor.execute('INSERT INTO bookings (event_id, service_id) VALUES (%s, %s)',
                 (event_id, service_id))
    mysql.connection.commit()
    
    flash('Service booked successfully!', 'success')
    return redirect('/organizer/dashboard')

@app.route('/organizer/bookings')
def organizer_bookings():
    if 'loggedin' not in session or session['role'] != 'organizer':
        return redirect('/login')
    
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    # Get organizer's bookings
    cursor.execute('''SELECT b.*, s.service_name, s.price, u.name as provider_name, e.event_name
                   FROM bookings b 
                   JOIN services s ON b.service_id = s.service_id 
                   JOIN events e ON b.event_id = e.event_id
                   JOIN users u ON s.provider_id = u.user_id
                   WHERE e.organizer_id = %s''', (session['user_id'],))
    bookings = cursor.fetchall()
    
    return render_template('organizer/bookings.html', bookings=bookings)

@app.route('/organizer/sponsorships')
def organizer_sponsorships():
    if 'loggedin' not in session or session['role'] != 'organizer':
        return redirect('/login')
    
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    # Get organizer's sponsorship requests
    cursor.execute('''SELECT sr.*, e.event_name 
                   FROM sponsorship_requests sr 
                   JOIN events e ON sr.event_id = e.event_id 
                   WHERE sr.organizer_id = %s''', (session['user_id'],))
    sponsorships = cursor.fetchall()
    
    # Get events for creating new sponsorship requests
    cursor.execute('SELECT * FROM events WHERE organizer_id = %s', (session['user_id'],))
    events = cursor.fetchall()
    
    return render_template('organizer/sponsorships.html', sponsorships=sponsorships, events=events)

@app.route('/organizer/create_sponsorship', methods=['POST'])
def create_sponsorship():
    if 'loggedin' not in session or session['role'] != 'organizer':
        return redirect('/login')
    
    event_id = request.form['event_id']
    details = request.form['details']
    sponsorship_amount = request.form.get('sponsorship_amount', 0)
    
    cursor = mysql.connection.cursor()
    cursor.execute('INSERT INTO sponsorship_requests (event_id, organizer_id, details, sponsorship_amount) VALUES (%s, %s, %s, %s)',
                 (event_id, session['user_id'], details, sponsorship_amount))
    mysql.connection.commit()
    
    flash('Sponsorship request created successfully!', 'success')
    return redirect('/organizer/sponsorships')

@app.route('/provider/dashboard')
def provider_dashboard():
    if 'loggedin' not in session or session['role'] != 'provider':
        return redirect('/login')
    
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    # Get provider's services
    cursor.execute('SELECT * FROM services WHERE provider_id = %s', (session['user_id'],))
    services = cursor.fetchall()
    
    # Get bookings for provider's services with organizer contact info AND price
    cursor.execute('''SELECT b.*, e.event_name, s.service_name, s.price, u.name as organizer_name, u.phone as organizer_phone
                   FROM bookings b 
                   JOIN services s ON b.service_id = s.service_id 
                   JOIN events e ON b.event_id = e.event_id 
                   JOIN users u ON e.organizer_id = u.user_id
                   WHERE s.provider_id = %s''', (session['user_id'],))
    bookings = cursor.fetchall()
    
    return render_template('provider/dashboard.html', services=services, bookings=bookings)

@app.route('/provider/add_service', methods=['GET', 'POST'])
def add_service():
    if 'loggedin' not in session or session['role'] != 'provider':
        return redirect('/login')
    
    if request.method == 'POST':
        service_name = request.form['service_name']
        price = request.form['price']
        description = request.form['description']
        availability = request.form['availability']
        
        cursor = mysql.connection.cursor()
        cursor.execute('INSERT INTO services (provider_id, service_name, price, description, availability) VALUES (%s, %s, %s, %s, %s)',
                     (session['user_id'], service_name, price, description, availability))
        mysql.connection.commit()
        flash('Service added successfully!', 'success')
        return redirect('/provider/dashboard')
    
    return render_template('provider/add_service.html')

@app.route('/provider/edit_service/<int:service_id>', methods=['GET', 'POST'])
def edit_service(service_id):
    if 'loggedin' not in session or session['role'] != 'provider':
        return redirect('/login')
    
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    if request.method == 'POST':
        service_name = request.form['service_name']
        price = request.form['price']
        description = request.form['description']
        availability = request.form['availability']
        
        cursor.execute('UPDATE services SET service_name=%s, price=%s, description=%s, availability=%s WHERE service_id=%s AND provider_id=%s',
                     (service_name, price, description, availability, service_id, session['user_id']))
        mysql.connection.commit()
        flash('Service updated successfully!', 'success')
        return redirect('/provider/dashboard')
    
    # GET request - show edit form
    cursor.execute('SELECT * FROM services WHERE service_id = %s AND provider_id = %s', (service_id, session['user_id']))
    service = cursor.fetchone()
    
    if service:
        return render_template('provider/edit_service.html', service=service)
    else:
        flash('Service not found!', 'danger')
        return redirect('/provider/dashboard')

@app.route('/provider/delete_service/<int:service_id>')
def delete_service(service_id):
    if 'loggedin' not in session or session['role'] != 'provider':
        return redirect(url_for('login'))
    
    try:
        cursor = mysql.connection.cursor()
        # First, delete any child records (bookings) that reference this service
        cursor.execute('DELETE FROM bookings WHERE service_id = %s', (service_id,))
        
        # Then, delete the parent record (service)
        cursor.execute('DELETE FROM services WHERE service_id = %s AND provider_id = %s', (service_id, session['user_id']))
        
        mysql.connection.commit()
        flash('Service and all associated bookings have been deleted successfully!', 'success')
    except Exception as e:
        # Rollback in case of an error
        mysql.connection.rollback()
        flash(f'An error occurred while trying to delete the service: {e}', 'danger')
    
    return redirect(url_for('provider_dashboard'))

@app.route('/provider/sponsorships')
def provider_sponsorships():
    if 'loggedin' not in session or session['role'] != 'provider':
        return redirect('/login')
    
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    # Get open sponsorship requests with organizer contact info
    cursor.execute('''SELECT sr.*, e.event_name, u.name as organizer_name, u.phone as organizer_phone, u.email as organizer_email
                   FROM sponsorship_requests sr 
                   JOIN events e ON sr.event_id = e.event_id 
                   JOIN users u ON sr.organizer_id = u.user_id 
                   WHERE sr.status = "open"''')
    sponsorships = cursor.fetchall()
    
    return render_template('provider/sponsorships.html', sponsorships=sponsorships)

@app.route('/provider/accept_sponsorship/<int:sponsorship_id>')
def accept_sponsorship(sponsorship_id):
    if 'loggedin' not in session or session['role'] != 'provider':
        return redirect('/login')
    
    provider_id = session['user_id']
    accepted_time = datetime.now()
    
    cursor = mysql.connection.cursor()
    cursor.execute('UPDATE sponsorship_requests SET status = "accepted", provider_id = %s, accepted_at = %s WHERE sponsorship_id = %s', 
                   (provider_id, accepted_time, sponsorship_id))
    mysql.connection.commit()
    
    flash('Sponsorship request accepted!', 'success')
    return redirect('/provider/sponsorships')

@app.route('/provider/accepted_sponsorships')
def provider_accepted_sponsorships():
    if 'loggedin' not in session or session['role'] != 'provider':
        return redirect('/login')

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    # Get sponsorships accepted by the current provider
    cursor.execute('''SELECT sr.*, e.event_name, u.name as organizer_name, u.phone as organizer_phone
                      FROM sponsorship_requests sr
                      JOIN events e ON sr.event_id = e.event_id
                      JOIN users u ON sr.organizer_id = u.user_id
                      WHERE sr.provider_id = %s AND sr.status = 'accepted'
                      ORDER BY sr.accepted_at DESC''', (session['user_id'],))
    sponsorships = cursor.fetchall()

    return render_template('provider/accepted_sponsorships.html', sponsorships=sponsorships)

@app.route('/provider/available_events')
def provider_available_events():
    if 'loggedin' not in session or session['role'] != 'provider':
        return redirect('/login')

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    # Get all upcoming events with organizer contact info
    cursor.execute('''SELECT e.*, u.name as organizer_name, u.phone as organizer_phone
                      FROM events e
                      JOIN users u ON e.organizer_id = u.user_id
                      WHERE e.status = 'upcoming'
                      ORDER BY e.event_date ASC''')
    events = cursor.fetchall()

    return render_template('provider/available_events.html', events=events)

@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('user_id', None)
    session.pop('name', None)
    session.pop('email', None)
    session.pop('role', None)
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)

