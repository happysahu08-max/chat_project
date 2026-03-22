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
from collections import defaultdict

CALL_RATE_PER_MINUTE = 1/1000

def deduct_call_charge(user_id, seconds):
    charge = seconds * (1/60000)
    cur = mysql.connection.cursor()
    cur.execute("SELECT wallet FROM users WHERE id=%s", (user_id,))
    wallet = cur.fetchone()[0]

    if wallet <= 0:
        return False

    cur.execute("""
        UPDATE users
        SET wallet = GREATEST(wallet - %s,0)
        WHERE id=%s
    """, (charge, user_id))

    mysql.connection.commit()
    return True

app = Flask(__name__)
app.secret_key = "chatsecret"

# MYSQL CONFIG
app.config['MYSQL_HOST'] = config.MYSQL_HOST
app.config['MYSQL_USER'] = config.MYSQL_USER
app.config['MYSQL_PASSWORD'] = config.MYSQL_PASSWORD
app.config['MYSQL_DB'] = config.MYSQL_DB

mysql = MySQL(app)

# Razorpay client
client = razorpay.Client(
    auth=(config.RAZORPAY_KEY, config.RAZORPAY_SECRET)
)

# ---------- WebRTC signaling in‑memory ----------
user_events = defaultdict(list)          # user_id -> list of events
user_call_status = defaultdict(lambda: None)   # user_id -> other_user_id
online_users = set()                     # user_ids with active sessions
last_ping = {}                           # user_id -> timestamp

def add_event(user_id, event):
    """Add an event for a user to be fetched via /api/call/events"""
    user_events[user_id].append(event)

def cleanup_stale_users():
    """Remove users who haven't pinged in last 60 seconds"""
    now = time.time()
    stale = [uid for uid, last in last_ping.items() if now - last > 60]
    for uid in stale:
        if uid in online_users:
            online_users.discard(uid)
        if uid in last_ping:
            del last_ping[uid]
        # Also clear call status if they were in a call
        other = user_call_status.get(uid)
        if other and other in online_users:
            user_call_status[other] = None
            add_event(other, {'type': 'call_ended', 'from': uid})
        user_call_status[uid] = None

# -------------------------------------------------------------------
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

            # Mark as online
            online_users.add(user[0])
            last_ping[user[0]] = time.time()
            cur.execute("UPDATE users SET online_status=1 WHERE id=%s", (user[0],))
            mysql.connection.commit()

            if user[4] == "admin":
                return redirect("/admin")
            else:
                return redirect("/admins")
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

    return render_template("admins.html", admins=admins)

@app.route("/user")
def user():
    if "id" not in session or session["role"] != "user":
        return redirect("/")

    admin_id = request.args.get("admin")
    call = request.args.get("call")

    cur = mysql.connection.cursor()
    cur.execute("SELECT id,name FROM users WHERE role='admin'")
    admins = cur.fetchall()

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
        uid = session["id"]
        if uid in online_users:
            online_users.discard(uid)
        if uid in last_ping:
            del last_ping[uid]
        cur = mysql.connection.cursor()
        cur.execute("UPDATE users SET online_status=0 WHERE id=%s", (uid,))
        mysql.connection.commit()

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

# ---------- CALL SIGNALING API (WebRTC) ----------
@app.route("/api/ping", methods=["POST"])
def ping():
    if "id" not in session:
        return jsonify({"error": "not logged in"}), 401
    uid = session["id"]
    last_ping[uid] = time.time()
    if uid not in online_users:
        online_users.add(uid)
    return jsonify({"status": "ok"})

@app.route("/api/users")
def get_users():
    cleanup_stale_users()
    if "id" not in session:
        return jsonify({"error": "not logged in"}), 401
    uid = session["id"]
    user_list = []
    for other in online_users:
        if other != uid:
            user_list.append({
                "id": other,
                "name": get_user_name(other),
                "in_call_with": user_call_status.get(other)
            })
    return jsonify(user_list)

def get_user_name(uid):
    cur = mysql.connection.cursor()
    cur.execute("SELECT name FROM users WHERE id=%s", (uid,))
    row = cur.fetchone()
    return row[0] if row else f"User{uid}"

@app.route("/api/call/initiate", methods=["POST"])
def call_initiate():
    if "id" not in session:
        return jsonify({"error": "not logged in"}), 401
    caller = session["id"]
    data = request.get_json()
    target = data.get("to")
    call_type = data.get("call_type", "audio")

    if target not in online_users:
        return jsonify({"error": "User offline"}), 400
    if user_call_status.get(target) is not None:
        return jsonify({"busy": True, "msg": "User is busy"}), 409

    # Create call record in database (for billing)
    cur = mysql.connection.cursor()
    cur.execute("""
        INSERT INTO calls(caller_id, receiver_id, status, call_type)
        VALUES(%s, %s, 'calling', %s)
    """, (caller, target, call_type))
    mysql.connection.commit()
    call_id = cur.lastrowid

    # Notify target of incoming call
    add_event(target, {
        "type": "incoming_call",
        "from": caller,
        "from_name": session["name"],
        "call_type": call_type,
        "call_id": call_id
    })
    return jsonify({"status": "calling", "call_id": call_id})

@app.route("/api/call/accept", methods=["POST"])
def call_accept():
    if "id" not in session:
        return jsonify({"error": "not logged in"}), 401
    answerer = session["id"]
    data = request.get_json()
    caller = data.get("from")

    # Update database call record
    cur = mysql.connection.cursor()
    cur.execute("""
        UPDATE calls
        SET status='accepted', start_time=NOW()
        WHERE caller_id=%s AND receiver_id=%s AND status='calling'
        ORDER BY id DESC LIMIT 1
    """, (caller, answerer))
    mysql.connection.commit()

    # Mark both as in call
    user_call_status[caller] = answerer
    user_call_status[answerer] = caller

    # Notify caller
    add_event(caller, {"type": "call_accepted", "from": answerer})
    return jsonify({"status": "accepted"})

@app.route("/api/call/reject", methods=["POST"])
def call_reject():
    if "id" not in session:
        return jsonify({"error": "not logged in"}), 401
    rejecter = session["id"]
    data = request.get_json()
    caller = data.get("from")

    # Update database
    cur = mysql.connection.cursor()
    cur.execute("""
        UPDATE calls
        SET status='rejected'
        WHERE caller_id=%s AND receiver_id=%s AND status='calling'
        ORDER BY id DESC LIMIT 1
    """, (caller, rejecter))
    mysql.connection.commit()

    # Notify caller
    add_event(caller, {"type": "call_rejected", "from": rejecter})
    return jsonify({"status": "rejected"})

@app.route("/api/call/offer", methods=["POST"])
def call_offer():
    if "id" not in session:
        return jsonify({"error": "not logged in"}), 401
    sender = session["id"]
    data = request.get_json()
    target = data.get("to")
    offer = data.get("offer")

    add_event(target, {"type": "offer", "from": sender, "offer": offer})
    return jsonify({"status": "ok"})

@app.route("/api/call/answer", methods=["POST"])
def call_answer():
    if "id" not in session:
        return jsonify({"error": "not logged in"}), 401
    sender = session["id"]
    data = request.get_json()
    target = data.get("to")
    answer = data.get("answer")

    add_event(target, {"type": "answer", "from": sender, "answer": answer})
    return jsonify({"status": "ok"})

@app.route("/api/call/ice", methods=["POST"])
def call_ice():
    if "id" not in session:
        return jsonify({"error": "not logged in"}), 401
    sender = session["id"]
    data = request.get_json()
    target = data.get("to")
    candidate = data.get("candidate")

    add_event(target, {"type": "ice", "from": sender, "candidate": candidate})
    return jsonify({"status": "ok"})

@app.route("/api/call/hangup", methods=["POST"])
def call_hangup():
    if "id" not in session:
        return jsonify({"error": "not logged in"}), 401
    uid = session["id"]
    other = user_call_status.get(uid)
    if other and other in online_users:
        # Notify other
        add_event(other, {"type": "call_ended", "from": uid})
        # Clear statuses
        user_call_status[uid] = None
        user_call_status[other] = None
    else:
        user_call_status[uid] = None

    # Update database call record (mark as ended)
    cur = mysql.connection.cursor()
    cur.execute("""
        UPDATE calls
        SET status='ended'
        WHERE (caller_id=%s OR receiver_id=%s) AND status IN ('calling','accepted')
        ORDER BY id DESC LIMIT 1
    """, (uid, uid))
    mysql.connection.commit()

    # If call was accepted and had start_time, charge
    cur.execute("""
        SELECT id, caller_id, start_time, status
        FROM calls
        WHERE (caller_id=%s OR receiver_id=%s) AND status='accepted'
        ORDER BY id DESC LIMIT 1
    """, (uid, uid))
    call = cur.fetchone()
    if call and call[2]:
        now = datetime.now()
        seconds = (now - call[2]).total_seconds()
        if seconds > 0:
            deduct_call_charge(call[1], seconds)

    return jsonify({"status": "ended"})

@app.route("/api/call/events")
def get_call_events():
    if "id" not in session:
        return jsonify({"error": "not logged in"}), 401
    uid = session["id"]
    events = user_events[uid][:]
    user_events[uid].clear()
    return jsonify(events)

# Existing call endpoints (kept for backward compatibility, but you can remove them)
@app.route("/start_call", methods=["POST"])
def start_call():
    return jsonify({"status": "use /api/call/initiate"}), 501

@app.route("/check_call")
def check_call():
    return jsonify({}), 501

@app.route("/accept_call/<cid>")
def accept_call(cid):
    return jsonify({"status": "use /api/call/accept"}), 501

@app.route("/reject_call/<cid>")
def reject_call(cid):
    return jsonify({"status": "use /api/call/reject"}), 501

@app.route("/call_status")
def call_status():
    return jsonify("none"), 501

@app.route("/end_call", methods=["POST"])
def end_call():
    return jsonify({"status": "use /api/call/hangup"}), 501

# ---------- RAZORPAY PAYMENT ----------
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
        """,(uid,amount,payment_id))

        cur.execute("""
        UPDATE users SET wallet = wallet + %s
        WHERE id=%s
        """,(amount,uid))

        mysql.connection.commit()

        return "success"

    except:
        return "payment verification failed"

# ---------- APPOINTMENT SYSTEM ----------
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

# ---------- ZEGOCLOUD TOKEN (optional) ----------
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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
