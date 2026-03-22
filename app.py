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

mysql = MySQL(app)

# WebRTC signaling storage
user_web_rtc_status = {}
user_web_rtc_events = defaultdict(list)

# Razorpay client
client = razorpay.Client(
    auth=(config.RAZORPAY_KEY, config.RAZORPAY_SECRET)
)

CALL_RATE_PER_MINUTE = 1/1000

def deduct_call_charge(user_id, seconds):
    charge = seconds * (CALL_RATE_PER_MINUTE / 60)  # Fixed calculation
    cur = mysql.connection.cursor()
    cur.execute("SELECT wallet FROM users WHERE id=%s", (user_id,))
    result = cur.fetchone()
    
    if not result:
        return False
        
    wallet = result[0]

    if wallet <= 0:
        return False

    cur.execute("""
        UPDATE users
        SET wallet = GREATEST(wallet - %s, 0)
        WHERE id=%s
    """, (charge, user_id))

    mysql.connection.commit()
    cur.close()
    return True

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
        cur.close()

        if user:
            session["id"] = user[0]
            session["role"] = user[4]
            session["name"] = user[1]

            if user[4] == "admin":
                return redirect("/admin")
            else:
                return redirect("/admins")
        else:
            return "Invalid credentials"

    return render_template("login.html")

# WebRTC Signaling Endpoints
@app.route('/api/webrtc/ping', methods=['POST'])
def webrtc_ping():
    """Keep WebRTC session alive"""
    if 'id' in session:
        user_web_rtc_status[session['id']] = time.time()
    return jsonify({'status': 'ok'})

@app.route('/api/webrtc/offer', methods=['POST'])
def webrtc_offer():
    """Send SDP offer to target user"""
    user_id = session.get('id')
    if not user_id:
        return jsonify({'error': 'Not logged in'}), 401
    
    data = request.get_json()
    target = data.get('to')
    offer = data.get('offer')
    
    if not target:
        return jsonify({'error': 'Target user required'}), 400
    
    # Store event for target user
    user_web_rtc_events[int(target)].append({
        'type': 'offer',
        'from': user_id,
        'offer': offer
    })
    return jsonify({'status': 'ok'})

@app.route('/api/webrtc/answer', methods=['POST'])
def webrtc_answer():
    """Send SDP answer to target user"""
    user_id = session.get('id')
    if not user_id:
        return jsonify({'error': 'Not logged in'}), 401
    
    data = request.get_json()
    target = data.get('to')
    answer = data.get('answer')
    
    if not target:
        return jsonify({'error': 'Target user required'}), 400
    
    user_web_rtc_events[int(target)].append({
        'type': 'answer',
        'from': user_id,
        'answer': answer
    })
    return jsonify({'status': 'ok'})

@app.route('/api/webrtc/ice', methods=['POST'])
def webrtc_ice():
    """Send ICE candidate to target user"""
    user_id = session.get('id')
    if not user_id:
        return jsonify({'error': 'Not logged in'}), 401
    
    data = request.get_json()
    target = data.get('to')
    candidate = data.get('candidate')
    
    if not target:
        return jsonify({'error': 'Target user required'}), 400
    
    user_web_rtc_events[int(target)].append({
        'type': 'ice',
        'from': user_id,
        'candidate': candidate
    })
    return jsonify({'status': 'ok'})

@app.route('/api/webrtc/events')
def webrtc_events():
    """Get WebRTC events for current user"""
    user_id = session.get('id')
    if not user_id:
        return jsonify({'error': 'Not logged in'}), 401
    
    events = user_web_rtc_events[user_id][:]
    user_web_rtc_events[user_id].clear()
    return jsonify(events)

@app.route('/api/webrtc/hangup', methods=['POST'])
def webrtc_hangup():
    """Handle call hangup"""
    user_id = session.get('id')
    if not user_id:
        return jsonify({'error': 'Not logged in'}), 401
    
    data = request.get_json()
    target = data.get('to')
    
    if target:
        user_web_rtc_events[int(target)].append({
            'type': 'hangup',
            'from': user_id
        })
    
    return jsonify({'status': 'ok'})

@app.route("/admin")
def admin():
    if "id" not in session or session["role"] != "admin":
        return redirect("/")

    cur = mysql.connection.cursor()
    cur.execute("UPDATE users SET online_status=1 WHERE id=%s", (session["id"],))
    mysql.connection.commit()
    cur.execute("SELECT id, name FROM users WHERE role='user'")
    users = cur.fetchall()
    cur.close()

    return render_template("admin.html", users=users)

@app.route("/admins")
def admins():
    if "id" not in session or session["role"] != "user":
        return redirect("/")

    cur = mysql.connection.cursor()
    cur.execute("""
    SELECT id, name, photo, rating, price_per_min, online_status
    FROM users
    WHERE role='admin'
    """)
    admins = cur.fetchall()
    cur.close()

    return render_template("admins.html", admins=admins)

@app.route("/user")
def user():
    if "id" not in session or session["role"] != "user":
        return redirect("/")

    admin_id = request.args.get("admin")
    call = request.args.get("call")

    cur = mysql.connection.cursor()
    cur.execute("SELECT id, name FROM users WHERE role='admin'")
    admins = cur.fetchall()
    cur.close()

    return render_template(
        "user.html",
        admin_id=admin_id,
        call=call,
        admins=admins,
        razorpay_key=config.RAZORPAY_KEY
    )

@app.route("/logout")
def logout():
    if "id" in session:
        cur = mysql.connection.cursor()
        cur.execute("UPDATE users SET online_status=0 WHERE id=%s", (session["id"],))
        mysql.connection.commit()
        cur.close()

    session.clear()
    return redirect("/")

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
    cur.close()
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
    cur.close()
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
    call_id = cur.lastrowid
    cur.close()
    
    return jsonify({"status": "calling", "call_id": call_id})

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
    cur.close()
    
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
    cur.close()
    return jsonify({"status": "accepted"})

@app.route("/reject_call/<cid>")
def reject_call(cid):
    cur = mysql.connection.cursor()
    cur.execute("UPDATE calls SET status='rejected' WHERE id=%s", (cid,))
    mysql.connection.commit()
    cur.close()
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
    cur.close()

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

        # If call already started, charge user
        if status == "accepted" and start_time:
            now = datetime.now()
            seconds = (now - start_time).total_seconds()
            deduct_call_charge(caller_id, seconds)

        cur.execute("UPDATE calls SET status='ended' WHERE id=%s", (call_id,))
        mysql.connection.commit()

    cur.close()
    return jsonify({"status": "ended"})

# ZEGOCLOUD TOKEN GENERATION (optional)
@app.route("/generate_zego_token", methods=["POST"])
def generate_zego_token():
    if "id" not in session:
        return jsonify({"error": "not_logged_in"}), 401
    
    try:
        user_id = request.form.get("user_id")
        room_id = request.form.get("room_id")
        
        if not user_id or not room_id:
            return jsonify({"error": "Missing parameters"}), 400
        
        app_id = config.ZEGO_APP_ID
        server_secret = config.ZEGO_SERVER_SECRET
        
        effective_time = 3600
        current_time = int(time.time())
        
        payload = {
            "app_id": app_id,
            "room_id": str(room_id),
            "user_id": str(user_id),
            "nonce": current_time,
            "ctime": current_time,
            "expire": effective_time
        }
        
        payload_json = json.dumps(payload, separators=(',', ':'))
        
        signature = hmac.new(
            server_secret.encode('utf-8'),
            payload_json.encode('utf-8'),
            hashlib.sha256
        ).digest()
        
        signature_base64 = base64.b64encode(signature).decode('utf-8')
        
        token_data = {
            "payload": payload_json,
            "signature": signature_base64
        }
        
        token = base64.b64encode(
            json.dumps(token_data).encode('utf-8')
        ).decode('utf-8')
        
        return jsonify({"token": token})
        
    except Exception as e:
        print(f"Token generation error: {str(e)}")
        return jsonify({"error": str(e)}), 500

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
        cur.close()

        return "success"

    except Exception as e:
        print(f"Payment verification failed: {e}")
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
    result = cur.fetchone()
    
    if not result:
        return "User not found"
        
    wallet = result[0]

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
    cur.close()
    return "Appointment booked successfully"

@app.route("/wallet")
def wallet():
    uid = session["id"]
    cur = mysql.connection.cursor()

    cur.execute("SELECT wallet FROM users WHERE id=%s", (uid,))
    result = cur.fetchone()
    cur.close()
    
    balance = result[0] if result else 0

    return jsonify({"balance": float(balance)})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
