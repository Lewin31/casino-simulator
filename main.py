"""
Casino Royale — Backend Server
FastAPI + SQLite + WebSocket
"""

from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, List
import sqlite3, hashlib, secrets, time, json, os, asyncio

app = FastAPI(title="Casino Royale API")

# ── CORS (разрешаем запросы с Netlify) ──────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer(auto_error=False)
DB_PATH  = "casino.db"

# ═══════════════════════════════════════════════════════════
#  БАЗА ДАННЫХ
# ═══════════════════════════════════════════════════════════
def get_db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    return con

def init_db():
    con = get_db()
    con.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        username    TEXT UNIQUE NOT NULL,
        password    TEXT NOT NULL,
        balance     INTEGER DEFAULT 1000,
        debt        INTEGER DEFAULT 0,
        debt_total  INTEGER DEFAULT 0,
        total_won   INTEGER DEFAULT 0,
        total_lost  INTEGER DEFAULT 0,
        rounds      INTEGER DEFAULT 0,
        roulette_rounds INTEGER DEFAULT 0,
        slots_rounds    INTEGER DEFAULT 0,
        crash_rounds    INTEGER DEFAULT 0,
        biggest_win INTEGER DEFAULT 0,
        avatar      TEXT DEFAULT '',
        created_at  INTEGER DEFAULT 0,
        last_seen   INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS tokens (
        token       TEXT PRIMARY KEY,
        user_id     INTEGER NOT NULL,
        created_at  INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS friends (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id     INTEGER NOT NULL,
        friend_id   INTEGER NOT NULL,
        status      TEXT DEFAULT 'pending',
        created_at  INTEGER DEFAULT 0,
        UNIQUE(user_id, friend_id)
    );
    CREATE TABLE IF NOT EXISTS messages (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id     INTEGER NOT NULL,
        username    TEXT NOT NULL,
        text        TEXT NOT NULL,
        created_at  INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS game_history (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id     INTEGER NOT NULL,
        mode        TEXT NOT NULL,
        bet         INTEGER NOT NULL,
        win         INTEGER NOT NULL,
        net         INTEGER NOT NULL,
        created_at  INTEGER DEFAULT 0
    );
    """)
    con.commit(); con.close()

init_db()

# ═══════════════════════════════════════════════════════════
#  ВСПОМОГАТЕЛЬНЫЕ
# ═══════════════════════════════════════════════════════════
def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def make_token() -> str:
    return secrets.token_hex(32)

def now() -> int:
    return int(time.time())

def get_user_by_token(token: str):
    if not token: return None
    con = get_db()
    row = con.execute(
        "SELECT u.* FROM users u JOIN tokens t ON t.user_id=u.id WHERE t.token=?", (token,)
    ).fetchone()
    if row:
        con.execute("UPDATE users SET last_seen=? WHERE id=?", (now(), row["id"]))
        con.commit()
    con.close()
    return dict(row) if row else None

def require_user(creds: HTTPAuthorizationCredentials = Depends(security)):
    token = creds.credentials if creds else None
    user  = get_user_by_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Не авторизован")
    return user

def user_to_public(u: dict) -> dict:
    return {
        "id":       u["id"],
        "username": u["username"],
        "balance":  u["balance"],
        "total_won":u["total_won"],
        "total_lost":u["total_lost"],
        "rounds":   u["rounds"],
        "biggest_win": u["biggest_win"],
        "avatar":   u["avatar"] or "",
        "last_seen":u["last_seen"],
        "online":   (now() - u["last_seen"]) < 60,
    }

# ═══════════════════════════════════════════════════════════
#  СХЕМЫ
# ═══════════════════════════════════════════════════════════
class RegisterBody(BaseModel):
    username: str
    password: str

class LoginBody(BaseModel):
    username: str
    password: str

class UpdateProfileBody(BaseModel):
    avatar: Optional[str] = None

class GameResultBody(BaseModel):
    mode:   str   # roulette | slots | crash
    bet:    int
    win:    int

class LoanBody(BaseModel):
    amount: int   # 500 | 1000 | 2500 | 5000

class SendMessageBody(BaseModel):
    text: str

class FriendActionBody(BaseModel):
    username: str

# ═══════════════════════════════════════════════════════════
#  AUTH
# ═══════════════════════════════════════════════════════════
@app.post("/auth/register")
def register(body: RegisterBody):
    if len(body.username) < 3:
        raise HTTPException(400, "Имя минимум 3 символа")
    if len(body.password) < 4:
        raise HTTPException(400, "Пароль минимум 4 символа")
    if not body.username.replace("_","").isalnum():
        raise HTTPException(400, "Только буквы, цифры и _")
    con = get_db()
    try:
        con.execute(
            "INSERT INTO users(username,password,created_at,last_seen) VALUES(?,?,?,?)",
            (body.username, hash_password(body.password), now(), now())
        )
        con.commit()
        user_id = con.execute("SELECT last_insert_rowid()").fetchone()[0]
        token   = make_token()
        con.execute("INSERT INTO tokens(token,user_id,created_at) VALUES(?,?,?)",
                    (token, user_id, now()))
        con.commit()
        user = dict(con.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone())
        con.close()
        return {"token": token, "user": user_to_public(user)}
    except sqlite3.IntegrityError:
        con.close()
        raise HTTPException(400, "Имя уже занято")

@app.post("/auth/login")
def login(body: LoginBody):
    con = get_db()
    user = con.execute(
        "SELECT * FROM users WHERE username=? AND password=?",
        (body.username, hash_password(body.password))
    ).fetchone()
    if not user:
        con.close()
        raise HTTPException(401, "Неверный логин или пароль")
    user = dict(user)
    token = make_token()
    con.execute("INSERT INTO tokens(token,user_id,created_at) VALUES(?,?,?)",
                (token, user["id"], now()))
    con.execute("UPDATE users SET last_seen=? WHERE id=?", (now(), user["id"]))
    con.commit(); con.close()
    return {"token": token, "user": user_to_public(user)}

@app.post("/auth/logout")
def logout(creds: HTTPAuthorizationCredentials = Depends(security)):
    if creds:
        con = get_db()
        con.execute("DELETE FROM tokens WHERE token=?", (creds.credentials,))
        con.commit(); con.close()
    return {"ok": True}

# ═══════════════════════════════════════════════════════════
#  ПРОФИЛЬ
# ═══════════════════════════════════════════════════════════
@app.get("/me")
def get_me(user=Depends(require_user)):
    return user_to_public(user)

@app.patch("/me")
def update_me(body: UpdateProfileBody, user=Depends(require_user)):
    con = get_db()
    if body.avatar is not None:
        con.execute("UPDATE users SET avatar=? WHERE id=?", (body.avatar, user["id"]))
    con.commit()
    updated = dict(con.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone())
    con.close()
    return user_to_public(updated)

@app.post("/game/result")
def save_result(body: GameResultBody, user=Depends(require_user)):
    con  = get_db()
    net  = body.win - body.bet
    mode = body.mode

    # Проверить баланс
    if body.bet > user["balance"]:
        con.close()
        raise HTTPException(400, "Недостаточно средств")

    updates = {
        "balance":    user["balance"] - body.bet + body.win,
        "rounds":     user["rounds"] + 1,
        f"{mode}_rounds": user.get(f"{mode}_rounds", 0) + 1,
    }
    if net > 0:
        updates["total_won"]   = user["total_won"] + net
        updates["biggest_win"] = max(user["biggest_win"], net)
    else:
        updates["total_lost"]  = user["total_lost"] + abs(net)

    # Авто-погашение долга
    if user["debt_total"] > 0 and body.win > 0:
        pay = min(user["debt_total"], body.win)
        updates["debt_total"] = user["debt_total"] - pay
        updates["debt"]       = max(0, user["debt"] - pay)

    set_clause = ", ".join(f"{k}=?" for k in updates)
    con.execute(f"UPDATE users SET {set_clause} WHERE id=?",
                list(updates.values()) + [user["id"]])
    con.execute(
        "INSERT INTO game_history(user_id,mode,bet,win,net,created_at) VALUES(?,?,?,?,?,?)",
        (user["id"], mode, body.bet, body.win, net, now())
    )
    con.commit()
    updated = dict(con.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone())
    con.close()
    return user_to_public(updated)

@app.post("/game/loan")
def take_loan(body: LoanBody, user=Depends(require_user)):
    if body.amount not in [500, 1000, 2500, 5000]:
        raise HTTPException(400, "Недопустимая сумма")
    repay = int(body.amount * 1.2)
    con   = get_db()
    con.execute("""UPDATE users SET
        balance=balance+?, debt=debt+?, debt_total=debt_total+?
        WHERE id=?""", (body.amount, body.amount, repay, user["id"]))
    con.commit()
    updated = dict(con.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone())
    con.close()
    return user_to_public(updated)

@app.get("/game/history")
def get_history(user=Depends(require_user)):
    con  = get_db()
    rows = con.execute(
        "SELECT * FROM game_history WHERE user_id=? ORDER BY created_at DESC LIMIT 50",
        (user["id"],)
    ).fetchall()
    con.close()
    return [dict(r) for r in rows]

# ═══════════════════════════════════════════════════════════
#  ЛИДЕРБОРД
# ═══════════════════════════════════════════════════════════
@app.get("/leaderboard")
def leaderboard():
    con  = get_db()
    rows = con.execute(
        "SELECT * FROM users ORDER BY total_won DESC LIMIT 20"
    ).fetchall()
    con.close()
    result = []
    for i, r in enumerate(rows):
        u = user_to_public(dict(r))
        u["rank_pos"] = i + 1
        result.append(u)
    return result

# ═══════════════════════════════════════════════════════════
#  ДРУЗЬЯ
# ═══════════════════════════════════════════════════════════
@app.post("/friends/add")
def add_friend(body: FriendActionBody, user=Depends(require_user)):
    if body.username == user["username"]:
        raise HTTPException(400, "Нельзя добавить себя")
    con = get_db()
    friend = con.execute("SELECT * FROM users WHERE username=?", (body.username,)).fetchone()
    if not friend:
        con.close()
        raise HTTPException(404, "Пользователь не найден")
    friend = dict(friend)
    try:
        con.execute(
            "INSERT INTO friends(user_id,friend_id,status,created_at) VALUES(?,?,?,?)",
            (user["id"], friend["id"], "pending", now())
        )
        con.commit()
    except sqlite3.IntegrityError:
        con.close()
        raise HTTPException(400, "Запрос уже отправлен")
    con.close()
    return {"ok": True, "message": f"Запрос отправлен {body.username}"}

@app.post("/friends/accept")
def accept_friend(body: FriendActionBody, user=Depends(require_user)):
    con = get_db()
    friend = con.execute("SELECT * FROM users WHERE username=?", (body.username,)).fetchone()
    if not friend:
        con.close()
        raise HTTPException(404, "Пользователь не найден")
    friend = dict(friend)
    con.execute(
        "UPDATE friends SET status='accepted' WHERE user_id=? AND friend_id=?",
        (friend["id"], user["id"])
    )
    # Взаимная дружба
    try:
        con.execute(
            "INSERT OR IGNORE INTO friends(user_id,friend_id,status,created_at) VALUES(?,?,?,?)",
            (user["id"], friend["id"], "accepted", now())
        )
    except Exception:
        pass
    con.commit(); con.close()
    return {"ok": True}

@app.post("/friends/decline")
def decline_friend(body: FriendActionBody, user=Depends(require_user)):
    con = get_db()
    friend = con.execute("SELECT * FROM users WHERE username=?", (body.username,)).fetchone()
    if not friend:
        con.close()
        raise HTTPException(404, "Пользователь не найден")
    con.execute("DELETE FROM friends WHERE user_id=? AND friend_id=?",
                (dict(friend)["id"], user["id"]))
    con.commit(); con.close()
    return {"ok": True}

@app.get("/friends")
def get_friends(user=Depends(require_user)):
    con  = get_db()
    rows = con.execute("""
        SELECT u.*, f.status FROM users u
        JOIN friends f ON f.friend_id=u.id
        WHERE f.user_id=? AND f.status='accepted'
    """, (user["id"],)).fetchall()
    pending = con.execute("""
        SELECT u.*, f.status FROM users u
        JOIN friends f ON f.friend_id=u.id
        WHERE f.user_id=? AND f.status='pending'
    """, (user["id"],)).fetchall()
    incoming = con.execute("""
        SELECT u.*, f.status FROM users u
        JOIN friends f ON f.user_id=u.id
        WHERE f.friend_id=? AND f.status='pending'
    """, (user["id"],)).fetchall()
    con.close()
    def to_friend(r):
        u = user_to_public(dict(r))
        return u
    return {
        "friends":  [to_friend(r) for r in rows],
        "pending":  [to_friend(r) for r in pending],
        "incoming": [to_friend(r) for r in incoming],
    }

@app.delete("/friends/{username}")
def remove_friend(username: str, user=Depends(require_user)):
    con = get_db()
    friend = con.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if friend:
        fid = dict(friend)["id"]
        con.execute("DELETE FROM friends WHERE (user_id=? AND friend_id=?) OR (user_id=? AND friend_id=?)",
                    (user["id"], fid, fid, user["id"]))
        con.commit()
    con.close()
    return {"ok": True}

# ═══════════════════════════════════════════════════════════
#  ЧАТ — REST
# ═══════════════════════════════════════════════════════════
@app.get("/chat/messages")
def get_messages():
    con  = get_db()
    rows = con.execute(
        "SELECT * FROM messages ORDER BY created_at DESC LIMIT 50"
    ).fetchall()
    con.close()
    return list(reversed([dict(r) for r in rows]))

@app.post("/chat/send")
def send_message(body: SendMessageBody, user=Depends(require_user)):
    if not body.text.strip():
        raise HTTPException(400, "Пустое сообщение")
    if len(body.text) > 300:
        raise HTTPException(400, "Слишком длинное сообщение")
    con = get_db()
    con.execute(
        "INSERT INTO messages(user_id,username,text,created_at) VALUES(?,?,?,?)",
        (user["id"], user["username"], body.text.strip(), now())
    )
    # Оставляем только 200 последних сообщений
    con.execute("""DELETE FROM messages WHERE id NOT IN
        (SELECT id FROM messages ORDER BY created_at DESC LIMIT 200)""")
    con.commit()
    msg_id = con.execute("SELECT last_insert_rowid()").fetchone()[0]
    msg    = dict(con.execute("SELECT * FROM messages WHERE id=?", (msg_id,)).fetchone())
    con.close()
    # Рассылаем через WebSocket
    asyncio.create_task(broadcast({"type":"chat","message":msg}))
    return msg

# ═══════════════════════════════════════════════════════════
#  WEBSOCKET — онлайн-статус и чат в реальном времени
# ═══════════════════════════════════════════════════════════
class ConnectionManager:
    def __init__(self):
        self.connections: dict[int, list[WebSocket]] = {}

    async def connect(self, ws: WebSocket, user_id: int):
        await ws.accept()
        if user_id not in self.connections:
            self.connections[user_id] = []
        self.connections[user_id].append(ws)

    def disconnect(self, ws: WebSocket, user_id: int):
        if user_id in self.connections:
            try: self.connections[user_id].remove(ws)
            except ValueError: pass
            if not self.connections[user_id]:
                del self.connections[user_id]

    async def send_to(self, user_id: int, data: dict):
        for ws in self.connections.get(user_id, []):
            try: await ws.send_json(data)
            except Exception: pass

    async def broadcast(self, data: dict):
        for uid, wss in list(self.connections.items()):
            for ws in wss:
                try: await ws.send_json(data)
                except Exception: pass

    def online_users(self) -> list:
        return list(self.connections.keys())

manager = ConnectionManager()

async def broadcast(data: dict):
    await manager.broadcast(data)

@app.websocket("/ws/{token}")
async def websocket_endpoint(ws: WebSocket, token: str):
    user = get_user_by_token(token)
    if not user:
        await ws.close(code=4001)
        return

    uid = user["id"]
    await manager.connect(ws, uid)

    # Уведомить всех что пользователь онлайн
    await manager.broadcast({"type":"online","user_id":uid,"username":user["username"],"online":True})

    try:
        while True:
            data = await ws.receive_text()
            try:
                msg = json.loads(data)
                # Пинг-понг для поддержания соединения
                if msg.get("type") == "ping":
                    await ws.send_json({"type":"pong"})
                    # Обновить last_seen
                    con = get_db()
                    con.execute("UPDATE users SET last_seen=? WHERE id=?", (now(), uid))
                    con.commit(); con.close()
            except Exception:
                pass
    except WebSocketDisconnect:
        manager.disconnect(ws, uid)
        await manager.broadcast({"type":"online","user_id":uid,"username":user["username"],"online":False})

# ═══════════════════════════════════════════════════════════
#  ОНЛАЙН-СТАТУС
# ═══════════════════════════════════════════════════════════
@app.get("/online")
def get_online():
    con  = get_db()
    # Онлайн = last_seen < 60 секунд назад
    rows = con.execute(
        "SELECT id, username, total_won, avatar FROM users WHERE last_seen > ?",
        (now() - 60,)
    ).fetchall()
    con.close()
    return [{"id":r["id"],"username":r["username"],
             "total_won":r["total_won"],"avatar":r["avatar"]or""} for r in rows]

# ═══════════════════════════════════════════════════════════
#  ПОИСК
# ═══════════════════════════════════════════════════════════
@app.get("/users/search/{query}")
def search_users(query: str, user=Depends(require_user)):
    if len(query) < 2:
        raise HTTPException(400, "Минимум 2 символа")
    con  = get_db()
    rows = con.execute(
        "SELECT * FROM users WHERE username LIKE ? AND id!=? LIMIT 10",
        (f"%{query}%", user["id"])
    ).fetchall()
    con.close()
    return [user_to_public(dict(r)) for r in rows]

# ═══════════════════════════════════════════════════════════
#  HEALTHCHECK
# ═══════════════════════════════════════════════════════════
@app.get("/")
def root():
    return {"status":"ok","app":"Casino Royale API"}
