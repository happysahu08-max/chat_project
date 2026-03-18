from flask import Flask, render_template, request, redirect, session, jsonify
from flask_mysqldb import MySQL
import config
import razorpay
from datetime import datetime
import time
import json
import hashlib
import hmac
import base64
import secrets
from collections import defaultdict

app = Flask(__name__)
app.secret_key = "chatsecret"

# MYSQL CONFIG
app.config['MYSQL_HOST'] = config.MYSQL_HOST
app.config['MYSQL_USER'] = config.MYSQL_USER
app.config['MYSQL_PASSWORD'] = config.MYSQL_PASSWORD
app.config['MYSQL_DB'] = config.MYSQL_DB
app.config['MYSQL_PORT'] = config.MYSQL_PORT

mysql = MySQL(app)

# Razorpay client
client = razorpay.Client(
    auth=(config.RAZORPAY_KEY, config.RAZORPAY_SECRET)
)

# WebRTC signaling storage
call_signaling = defaultdict(list)
call_status_webrtc = {}  # track who's in a call
online_users = set()
user_sessions = {}

# Clean stale users
def clean_stale_users():
    now = time.time()
    stale = [u for u, last in list(user_sessions.items()) if now - last > 60]
    for u in stale:
        if u in online_users:
            online_users.remove(u)
        if u in user_sessions:
            del user_sessions[u]

# LOGIN
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        cur = mysql.connection.cursor()
        cur.execute(
            "SELECT * FROM users WHERE email=%s AND password=%s",
            (email, password)
        )
        user = cur.fetchone()

        if user:
            session["id"] = user[0]
            session["role"] = user[4]
            session["name"] = user[1]
            session.permanent = True
            
            # Add to online users
            user_id = str(user[0])
            online_users.add(user_id)
            user_sessions[user_id] = time.time()

            if user[4] == "admin":
                return redirect("/admin")
            else:
                return redirect("/user")
        else:
            return "Invalid credentials"

    return render_template("login.html")

@app.route("/admin")
def admin():
    if "id" not in session or session["role"] != "admin":
        return redirect("/")

    cur = mysql.connection.cursor()
    cur.execute("UPDATE users SET online_status=1 WHERE id=%s", (session["id"],))
    mysql.connection.commit()
    cur.execute("SELECT id, name FROM users WHERE role='user'")
    users = cur.fetchall()

    return render_template("admin.html", users=users, username=session["name"])

@app.route("/user")
def user():
    if "id" not in session or session["role"] != "user":
        return redirect("/")

    admin_id = request.args.get("admin")
    call = request.args.get("call")

    cur = mysql.connection.cursor()
    cur.execute("SELECT id, name FROM users WHERE role='admin'")
    admins = cur.fetchall()

    return render_template(
        "user.html",
        admin_id=admin_id,
        call=call,
        admins=admins,
        razorpay_key=config.RAZORPAY_KEY,
        username=session["name"]
    )

@app.route("/logout")
def logout():
    if "id" in session:
        user_id = str(session["id"])
        if user_id in online_users:
            online_users.remove(user_id)
        if user_id in user_sessions:
            del user_sessions[user_id]
        
        cur = mysql.connection.cursor()
        cur.execute("UPDATE users SET online_status=0 WHERE id=%s", (session["id"],))
        mysql.connection.commit()

    session.clear()
    return redirect("/")

@app.route("/api/ping", methods=["POST"])
def ping():
    """Keep session alive"""
    if "id" in session:
        user_sessions[str(session["id"])] = time.time()
    return jsonify({"status": "ok"})

@app.route("/api/online-users")
def get_online_users():
    clean_stale_users()
    if "id" not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    user_id = str(session["id"])
    users_list = []
    
    cur = mysql.connection.cursor()
    if session["role"] == "admin":
        cur.execute("SELECT id, name FROM users WHERE role='user'")
    else:
        cur.execute("SELECT id, name FROM users WHERE role='admin'")
    
    all_users = cur.fetchall()
    
    for u in all_users:
        uid = str(u[0])
        if uid != user_id:
            users_list.append({
                "id": uid,
                "name": u[1],
                "online": uid in online_users,
                "in_call_with": call_status_webrtc.get(uid)
            })
    
    return jsonify(users_list)

@app.route("/send", methods=["POST"])
def send():
    sender = session["id"]
    receiver = request.form.get("receiver")
    message = request.form.get("message")

    cur = mysql.connection.cursor()
    cur.execute("""
        INSERT INTO messages(sender_id, receiver_id, message)
        VALUES(%s, %s, %s)
    """, (sender, receiver, message))

    mysql.connection.commit()
    return "ok"

@app.route("/messages/<rid>")
def messages(rid):
    uid = session["id"]

    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT users.name, messages.message
        FROM messages
        JOIN users ON users.id = messages.sender_id
        WHERE (sender_id=%s AND receiver_id=%s)
        OR (sender_id=%s AND receiver_id=%s)
        ORDER BY messages.id ASC
    """, (uid, rid, rid, uid))

    data = cur.fetchall()
    return jsonify(data)

# CALL SYSTEM
@app.route("/start_call", methods=["POST"])
def start_call():
    caller = session["id"]
    receiver = request.form["receiver"]
    call_type = request.form.get("call_type", "audio")

    cur = mysql.connection.cursor()
    
    # End any existing active calls
    cur.execute("""
        UPDATE calls SET status='ended' 
        WHERE (caller_id=%s OR receiver_id=%s) AND status IN ('calling', 'accepted')
    """, (caller, caller))
    
    # Create new call with call_type
    cur.execute("""
        INSERT INTO calls(caller_id, receiver_id, status, call_type)
        VALUES(%s, %s, 'calling', %s)
    """, (caller, receiver, call_type))

    mysql.connection.commit()
    return jsonify({"status": "calling", "call_id": cur.lastrowid})

@app.route("/check_call")
def check_call():
    uid = session["id"]

    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT calls.id, users.name, calls.caller_id, calls.call_type
        FROM calls
        JOIN users ON users.id = calls.caller_id
        WHERE receiver_id=%s AND status='calling'
        ORDER BY id DESC LIMIT 1
    """, (uid,))

    call = cur.fetchone()
    if call:
        return jsonify({
            'id': call[0],
            'name': call[1],
            'caller_id': call[2],
            'call_type': call[3]
        })
    return jsonify({})

@app.route("/accept_call/<cid>")
def accept_call(cid):
    cur = mysql.connection.cursor()
    cur.execute("""
    UPDATE calls
    SET status='accepted', start_time=NOW()
    WHERE id=%s
    """, (cid,))

    mysql.connection.commit()
    return jsonify({"status": "accepted"})

@app.route("/reject_call/<cid>")
def reject_call(cid):
    cur = mysql.connection.cursor()
    cur.execute("UPDATE calls SET status='rejected' WHERE id=%s", (cid,))
    mysql.connection.commit()
    return jsonify({"status": "rejected"})

@app.route("/call_status")
def call_status():
    uid = session["id"]

    cur = mysql.connection.cursor()
    cur.execute("""
    SELECT status 
    FROM calls
    WHERE (caller_id=%s OR receiver_id=%s)
    ORDER BY id DESC LIMIT 1
    """, (uid, uid))

    data = cur.fetchone()

    if data:
        return jsonify(data[0])

    return jsonify("none")

@app.route("/end_call", methods=["POST"])
def end_call():
    uid = session["id"]
    cur = mysql.connection.cursor()

    # Find latest active call
    cur.execute("""
    SELECT id, caller_id, start_time, status
    FROM calls
    WHERE (caller_id=%s OR receiver_id=%s)
    AND status IN ('calling','accepted')
    ORDER BY id DESC LIMIT 1
    """, (uid, uid))

    call = cur.fetchone()

    if call:
        call_id, caller_id, start_time, status = call

        cur.execute("UPDATE calls SET status='ended' WHERE id=%s", (call_id,))
        mysql.connection.commit()

    return jsonify({"status": "ended"})

# WebRTC Signaling Endpoints
@app.route("/webrtc/offer", methods=["POST"])
def webrtc_offer():
    """Handle WebRTC offer"""
    if "id" not in session:
        return jsonify({"error": "not_logged_in"}), 401
    
    data = request.get_json()
    target = str(data.get("target"))
    offer = data.get("offer")
    call_type = data.get("call_type", "audio")
    
    # Store offer for target
    call_signaling[target].append({
        "type": "offer",
        "from": str(session["id"]),
        "offer": offer,
        "call_type": call_type
    })
    
    return jsonify({"status": "ok"})

@app.route("/webrtc/answer", methods=["POST"])
def webrtc_answer():
    """Handle WebRTC answer"""
    if "id" not in session:
        return jsonify({"error": "not_logged_in"}), 401
    
    data = request.get_json()
    target = str(data.get("target"))
    answer = data.get("answer")
    
    call_signaling[target].append({
        "type": "answer",
        "from": str(session["id"]),
        "answer": answer
    })
    
    return jsonify({"status": "ok"})

@app.route("/webrtc/ice", methods=["POST"])
def webrtc_ice():
    """Handle ICE candidate"""
    if "id" not in session:
        return jsonify({"error": "not_logged_in"}), 401
    
    data = request.get_json()
    target = str(data.get("target"))
    candidate = data.get("candidate")
    
    call_signaling[target].append({
        "type": "ice",
        "from": str(session["id"]),
        "candidate": candidate
    })
    
    return jsonify({"status": "ok"})

@app.route("/webrtc/events")
def webrtc_events():
    """Get signaling events for current user"""
    if "id" not in session:
        return jsonify({"error": "not_logged_in"}), 401
    
    user_id = str(session["id"])
    events = call_signaling.get(user_id, [])
    
    # Clear after retrieving
    if user_id in call_signaling:
        call_signaling[user_id] = []
    
    return jsonify(events)

@app.route("/webrtc/call/accept", methods=["POST"])
def webrtc_accept_call():
    """Accept a call"""
    if "id" not in session:
        return jsonify({"error": "not_logged_in"}), 401
    
    data = request.get_json()
    caller_id = str(data.get("caller_id"))
    user_id = str(session["id"])
    
    # Mark both users as in call
    call_status_webrtc[user_id] = caller_id
    call_status_webrtc[caller_id] = user_id
    
    # Update call in database
    cur = mysql.connection.cursor()
    cur.execute("""
        UPDATE calls SET status='accepted', start_time=NOW()
        WHERE (caller_id=%s AND receiver_id=%s) OR (caller_id=%s AND receiver_id=%s)
    """, (caller_id, session["id"], session["id"], caller_id))
    mysql.connection.commit()
    
    return jsonify({"status": "accepted"})

@app.route("/webrtc/call/end", methods=["POST"])
def webrtc_end_call():
    """End a call"""
    if "id" not in session:
        return jsonify({"error": "not_logged_in"}), 401
    
    user_id = str(session["id"])
    other_id = call_status_webrtc.get(user_id)
    
    if other_id:
        # Notify other user
        call_signaling[other_id].append({
            "type": "call_ended",
            "from": user_id
        })
        
        # Remove from call status
        if other_id in call_status_webrtc:
            del call_status_webrtc[other_id]
    
    if user_id in call_status_webrtc:
        del call_status_webrtc[user_id]
    
    # Update database
    cur = mysql.connection.cursor()
    cur.execute("""
        UPDATE calls SET status='ended' 
        WHERE (caller_id=%s OR receiver_id=%s) AND status='accepted'
    """, (session["id"], session["id"]))
    mysql.connection.commit()
    
    return jsonify({"status": "ok"})

@app.route("/webrtc/call/status")
def webrtc_call_status():
    """Get current call status"""
    if "id" not in session:
        return jsonify({"error": "not_logged_in"}), 401
    
    user_id = str(session["id"])
    in_call_with = call_status_webrtc.get(user_id)
    
    if in_call_with:
        return jsonify({
            "in_call": True,
            "with": in_call_with
        })
    else:
        return jsonify({
            "in_call": False
        })

# RAZORPAY PAYMENT
@app.route("/create_order", methods=["POST"])
def create_order():
    amount = int(request.form["amount"]) * 100
    order = client.order.create({
        "amount": amount,
        "currency": "INR",
        "payment_capture": 1
    })
    return jsonify(order)

@app.route("/payment_success", methods=["POST"])
def payment_success():
    uid = session["id"]

    payment_id = request.form["razorpay_payment_id"]
    order_id = request.form["razorpay_order_id"]
    signature = request.form["razorpay_signature"]
    amount = request.form["amount"]

    params = {
        "razorpay_order_id": order_id,
        "razorpay_payment_id": payment_id,
        "razorpay_signature": signature
    }

    try:
        client.utility.verify_payment_signature(params)

        cur = mysql.connection.cursor()

        cur.execute("""
        INSERT INTO payments(user_id, amount, razorpay_payment_id, status)
        VALUES(%s,%s,%s,'success')
        """, (uid, amount, payment_id))

        cur.execute("""
        UPDATE users SET wallet = wallet + %s
        WHERE id=%s
        """, (amount, uid))

        mysql.connection.commit()

        return "success"

    except:
        return "payment verification failed"

# APPOINTMENT SYSTEM
@app.route("/book_appointment", methods=["POST"])
def book_appointment():
    uid = session["id"]
    admin = 1
    time = request.form.get("time")

    if not time:
        return "Please select appointment time"

    cur = mysql.connection.cursor()
    cur.execute("SELECT wallet FROM users WHERE id=%s", (uid,))
    wallet = cur.fetchone()[0]

    if wallet < 100:
        return "Recharge first"

    cur.execute("""
        INSERT INTO appointments(user_id, admin_id, appointment_time)
        VALUES(%s, %s, %s)
    """, (uid, admin, time))
    
    cur.execute("""
        UPDATE users SET wallet = wallet - 100
        WHERE id=%s
    """, (uid,))

    mysql.connection.commit()
    return "Appointment booked successfully"

@app.route("/wallet")
def wallet():
    uid = session["id"]
    cur = mysql.connection.cursor()

    cur.execute("SELECT wallet FROM users WHERE id=%s", (uid,))
    balance = cur.fetchone()[0]

    return jsonify({"balance": float(balance)})




def create_tables():
    cur = mysql.connection.cursor()

    # USERS TABLE
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100),
        email VARCHAR(100),
        password VARCHAR(100),
        role VARCHAR(20),
        wallet DECIMAL(10,2) DEFAULT 0,
        photo VARCHAR(255),
        rating FLOAT DEFAULT 4.5,
        price_per_min INT DEFAULT 10,
        online_status TINYINT DEFAULT 1
    )
    """)

    # OTHER TABLES
    cur.execute("""
    CREATE TABLE IF NOT EXISTS messages (
        id INT AUTO_INCREMENT PRIMARY KEY,
        sender_id INT,
        receiver_id INT,
        message TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS calls (
        id INT AUTO_INCREMENT PRIMARY KEY,
        caller_id INT,
        receiver_id INT,
        status VARCHAR(20),
        start_time DATETIME,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        call_type VARCHAR(10)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS payments (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        amount INT,
        razorpay_payment_id VARCHAR(200),
        status VARCHAR(50),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS appointments (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        admin_id INT,
        appointment_time DATETIME,
        status VARCHAR(50)
    )
    """)

    # DEFAULT USERS (NO DUPLICATE)
    cur.execute("""
    INSERT IGNORE INTO users(name,email,password,role,wallet)
    VALUES('Admin','admin@gmail.com','admin123','admin',0)
    """)

    cur.execute("""
    INSERT IGNORE INTO users(name,email,password,role,wallet)
    VALUES('User1','user@gmail.com','1234','user',10)
    """)

    cur.execute("""
    INSERT IGNORE INTO users(name,email,password,role)
    VALUES
    ('Krushna','krushna@gmail.com','krushna123','admin'),
    ('Rahul','rahul@gmail.com','rahul123','admin'),
    ('Amit','amit@gmail.com','amit123','admin')
    """)

    mysql.connection.commit()
    cur.close()

import os

if __name__ == "__main__":
    with app.app_context():
        create_tables()

    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
