import { useEffect, useState, useCallback } from "react";
import { BrowserRouter, Routes, Route, useNavigate, Link } from "react-router-dom";
import axios from "axios";
import { Toaster, toast } from "@/components/ui/sonner.jsx";
import { Button } from "@/components/ui/button.jsx";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card.jsx";
import { Input } from "@/components/ui/input.jsx";
import { Label } from "@/components/ui/label.jsx";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs.jsx";
import { Textarea } from "@/components/ui/textarea.jsx";
import { Badge } from "@/components/ui/badge.jsx";
import "@/App.css";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const api = axios.create({ baseURL: API, withCredentials: true });

// ─── Auth hook ────────────────────────────────────────────────────────────────
function useAuth() {
  const [me, setMe] = useState(null);
  const [loading, setLoading] = useState(true);
  const fetchMe = useCallback(async () => {
    try {
      const res = await api.get("/auth/me");
      setMe(res.data);
    } catch {
      setMe(null);
    } finally {
      setLoading(false);
    }
  }, []);
  useEffect(() => { fetchMe(); }, [fetchMe]);
  return { me, loading, refresh: fetchMe };
}

// ─── Auth Page ─────────────────────────────────────────────────────────────────
function AuthPage() {
  const nav = useNavigate();
  const { refresh } = useAuth();
  const [login, setLogin] = useState({ username: "", password: "" });
  const [reg, setReg] = useState({ username: "", email: "", password: "" });

  const doLogin = async () => {
    try {
      await api.post("/auth/login", login);
      toast.success("Logged in");
      await refresh();
      nav("/messages");
    } catch (e) {
      toast.error(e?.response?.data?.detail || "Login failed");
    }
  };

  const doRegister = async () => {
    try {
      await api.post("/auth/register", reg);
      toast.success("Registered. You can log in now.");
    } catch (e) {
      toast.error(e?.response?.data?.detail || "Registration failed");
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-b from-teal-50 via-white to-emerald-50">
      <div className="max-w-4xl mx-auto px-6 py-16">
        <div className="mb-10">
          <h1 className="font-['Space_Grotesk'] text-5xl md:text-6xl font-bold text-slate-800 tracking-tight" data-testid="app-title">
            Secure XML Messaging
          </h1>
          <p className="mt-3 text-slate-600 text-lg" data-testid="app-subtitle">
            Login or create an account to send encrypted &amp; signed XML messages.
          </p>
        </div>
        <Card className="shadow-xl border-0 ring-1 ring-slate-100/70 backdrop-blur-xl bg-white/90" data-testid="auth-card">
          <CardHeader>
            <CardTitle className="text-slate-800">Welcome</CardTitle>
            <CardDescription>Authenticate to continue</CardDescription>
          </CardHeader>
          <CardContent>
            <Tabs defaultValue="login" className="w-full" data-testid="auth-tabs">
              <TabsList className="grid grid-cols-2 w-full">
                <TabsTrigger value="login" data-testid="login-tab">Login</TabsTrigger>
                <TabsTrigger value="register" data-testid="register-tab">Register</TabsTrigger>
              </TabsList>
              <TabsContent value="login">
                <div className="grid gap-4 pt-4">
                  <div className="grid gap-2">
                    <Label htmlFor="l-username">Username</Label>
                    <Input id="l-username" data-testid="login-username-input" value={login.username} onChange={e => setLogin({ ...login, username: e.target.value })} placeholder="alice" onKeyDown={e => e.key === "Enter" && doLogin()} />
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="l-password">Password</Label>
                    <Input id="l-password" data-testid="login-password-input" type="password" value={login.password} onChange={e => setLogin({ ...login, password: e.target.value })} placeholder="••••••" onKeyDown={e => e.key === "Enter" && doLogin()} />
                  </div>
                  <Button data-testid="login-submit-button" onClick={doLogin} className="justify-center bg-emerald-600 hover:bg-emerald-700 text-white rounded-full">Login</Button>
                </div>
              </TabsContent>
              <TabsContent value="register">
                <div className="grid gap-4 pt-4">
                  <div className="grid gap-2">
                    <Label htmlFor="r-username">Username</Label>
                    <Input id="r-username" data-testid="register-username-input" value={reg.username} onChange={e => setReg({ ...reg, username: e.target.value })} placeholder="newuser" />
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="r-email">Email</Label>
                    <Input id="r-email" data-testid="register-email-input" type="email" value={reg.email} onChange={e => setReg({ ...reg, email: e.target.value })} placeholder="you@example.com" />
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="r-password">Password</Label>
                    <Input id="r-password" data-testid="register-password-input" type="password" value={reg.password} onChange={e => setReg({ ...reg, password: e.target.value })} placeholder="••••••" />
                  </div>
                  <Button data-testid="register-submit-button" onClick={doRegister} className="justify-center bg-teal-600 hover:bg-teal-700 text-white rounded-full">Create account</Button>
                </div>
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>
      </div>
      <Toaster position="top-right" richColors />
    </div>
  );
}

// ─── Profile Page ──────────────────────────────────────────────────────────────
function ProfilePage() {
  const nav = useNavigate();
  const { me, refresh } = useAuth();
  const [form, setForm] = useState({ email: "", current_password: "", new_password: "", confirm_password: "" });
  const [saving, setSaving] = useState(false);

  useEffect(() => { if (me) setForm(f => ({ ...f, email: me.email })); }, [me]);

  const save = async () => {
    if (form.new_password && form.new_password !== form.confirm_password) {
      toast.error("New passwords do not match");
      return;
    }
    setSaving(true);
    try {
      const payload = {};
      if (form.email !== me?.email) payload.email = form.email;
      if (form.new_password) {
        payload.current_password = form.current_password;
        payload.new_password = form.new_password;
      }
      await api.patch("/auth/profile", payload);
      toast.success("Profile updated");
      await refresh();
      setForm(f => ({ ...f, current_password: "", new_password: "", confirm_password: "" }));
    } catch (e) {
      toast.error(e?.response?.data?.detail || "Update failed");
    } finally {
      setSaving(false);
    }
  };

  if (!me) return null;

  return (
    <div className="min-h-screen bg-gradient-to-b from-emerald-50 via-white to-teal-50">
      <div className="max-w-2xl mx-auto px-6 py-10">
        <div className="flex items-center gap-4 mb-8">
          <Button variant="outline" onClick={() => nav("/messages")} className="rounded-full">← Back</Button>
          <h2 className="font-['Space_Grotesk'] text-3xl font-semibold text-slate-800">Profile Settings</h2>
        </div>

        <Card className="border-0 shadow-xl ring-1 ring-slate-100/70">
          <CardHeader>
            <CardTitle>Account Info</CardTitle>
            <CardDescription>Update your email or change your password</CardDescription>
          </CardHeader>
          <CardContent className="space-y-5">
            <div className="p-3 bg-slate-50 rounded-lg">
              <p className="text-sm text-slate-500">Username</p>
              <p className="font-semibold text-slate-800">@{me.username}</p>
            </div>

            <div className="space-y-2">
              <Label>Email</Label>
              <Input type="email" value={form.email} onChange={e => setForm({ ...form, email: e.target.value })} />
            </div>

            <div className="border-t pt-4 mt-4">
              <p className="font-medium text-slate-700 mb-3">Change Password</p>
              <div className="space-y-3">
                <div className="space-y-1">
                  <Label>Current Password</Label>
                  <Input type="password" value={form.current_password} onChange={e => setForm({ ...form, current_password: e.target.value })} placeholder="Required to change password" />
                </div>
                <div className="space-y-1">
                  <Label>New Password</Label>
                  <Input type="password" value={form.new_password} onChange={e => setForm({ ...form, new_password: e.target.value })} placeholder="Leave blank to keep current" />
                </div>
                <div className="space-y-1">
                  <Label>Confirm New Password</Label>
                  <Input type="password" value={form.confirm_password} onChange={e => setForm({ ...form, confirm_password: e.target.value })} placeholder="Repeat new password" />
                </div>
              </div>
            </div>

            <Button onClick={save} disabled={saving} className="bg-emerald-600 hover:bg-emerald-700 text-white rounded-full w-full">
              {saving ? "Saving…" : "Save Changes"}
            </Button>
          </CardContent>
        </Card>
      </div>
      <Toaster position="top-right" richColors />
    </div>
  );
}

// ─── Message List Item Component ───────────────────────────────────────────────
function MsgRow({ m, isInbox, onViewXml, onDecrypt, onDelete, onReply }) {
  const [showThread, setShowThread] = useState(false);
  const [thread, setThread] = useState([]);

  const loadThread = async () => {
    if (!showThread) {
      try {
        const res = await api.get(`/messages/${m.id}/thread`);
        setThread(res.data);
      } catch {}
    }
    setShowThread(v => !v);
  };

  return (
    <li className={`rounded-lg p-3 border ${m.is_read === false && isInbox ? "bg-emerald-50 border-emerald-200" : "bg-white/70 border-slate-100"}`}
      data-testid={`${isInbox ? "inbox" : "sent"}-item-${m.id}`}>
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            {isInbox && !m.is_read && <span className="w-2 h-2 rounded-full bg-emerald-500 shrink-0 mt-1" />}
            <span className="text-slate-800 font-medium truncate">
              {isInbox ? `From ${m.sender}` : `To ${m.recipient}`}
            </span>
            {m.reply_to && <Badge variant="outline" className="text-xs shrink-0">Reply</Badge>}
            {!m.signature_valid && <Badge variant="destructive" className="text-xs shrink-0">⚠ Invalid sig</Badge>}
          </div>
          <div className="text-xs text-slate-500 mt-0.5">{new Date(m.created_at).toLocaleString()}</div>
        </div>
        <div className="flex gap-1 shrink-0 flex-wrap justify-end">
          <Button size="sm" variant="outline" onClick={() => onViewXml(m.id)} data-testid={`view-xml-${m.id}`}>XML</Button>
          <Button size="sm" className="bg-slate-800 hover:bg-slate-900 text-white" onClick={() => onDecrypt(m.id)} data-testid={`decrypt-${m.id}`}>Decrypt</Button>
          <Button size="sm" variant="outline" onClick={() => onReply(m)} title="Reply">↩</Button>
          <Button size="sm" variant="outline" onClick={loadThread} title="Thread">💬</Button>
          <Button size="sm" variant="outline" className="text-red-500 hover:text-red-700 hover:bg-red-50" onClick={() => onDelete(m.id)} data-testid={`delete-${m.id}`}>🗑</Button>
        </div>
      </div>

      {showThread && (
        <div className="mt-3 pl-4 border-l-2 border-emerald-200 space-y-2">
          {thread.length === 0
            ? <p className="text-xs text-slate-400">No replies yet.</p>
            : thread.map(r => (
              <div key={r.id} className="text-xs bg-white rounded p-2 shadow-sm">
                <span className="font-medium">{r.sender}</span> → <span>{r.recipient}</span>
                <span className="ml-2 text-slate-400">{new Date(r.created_at).toLocaleString()}</span>
                <div className="flex gap-1 mt-1">
                  <Button size="sm" variant="outline" className="h-5 text-xs px-1" onClick={() => onDecrypt(r.id)}>Decrypt</Button>
                  <Button size="sm" variant="outline" className="h-5 text-xs px-1 text-red-500" onClick={() => onDelete(r.id)}>🗑</Button>
                </div>
              </div>
            ))
          }
        </div>
      )}
    </li>
  );
}

// ─── Search Bar ────────────────────────────────────────────────────────────────
function SearchBar({ value, dateFrom, dateTo, onChange, onDateFrom, onDateTo, placeholder }) {
  return (
    <div className="flex gap-2 flex-wrap mb-3">
      <Input className="flex-1 min-w-32" placeholder={placeholder} value={value} onChange={e => onChange(e.target.value)} />
      <Input type="date" className="w-36" value={dateFrom} onChange={e => onDateFrom(e.target.value)} />
      <Input type="date" className="w-36" value={dateTo} onChange={e => onDateTo(e.target.value)} />
    </div>
  );
}

// ─── Messages Page ─────────────────────────────────────────────────────────────
function MessagesPage() {
  const nav = useNavigate();
  const { me, refresh } = useAuth();

  const [compose, setCompose] = useState({ recipient: "", body: "", metadata: "", reply_to: null });
  const [replyLabel, setReplyLabel] = useState(null);
  const [inbox, setInbox] = useState([]);
  const [sent, setSent] = useState([]);
  const [unread, setUnread] = useState(0);
  const [selectedXml, setSelectedXml] = useState("");
  const [decrypted, setDecrypted] = useState(null);
  const [users, setUsers] = useState([]);

  // Search state
  const [inboxSearch, setInboxSearch] = useState("");
  const [inboxDateFrom, setInboxDateFrom] = useState("");
  const [inboxDateTo, setInboxDateTo] = useState("");
  const [sentSearch, setSentSearch] = useState("");
  const [sentDateFrom, setSentDateFrom] = useState("");
  const [sentDateTo, setSentDateTo] = useState("");

  const load = useCallback(async () => {
    try {
      const [ib, st, uc, ul] = await Promise.all([
        api.get("/messages/inbox", { params: { search: inboxSearch || undefined, date_from: inboxDateFrom || undefined, date_to: inboxDateTo || undefined } }),
        api.get("/messages/sent", { params: { search: sentSearch || undefined, date_from: sentDateFrom || undefined, date_to: sentDateTo || undefined } }),
        api.get("/messages/unread-count"),
        api.get("/users"),
      ]);
      setInbox(ib.data);
      setSent(st.data);
      setUnread(uc.data.count);
      setUsers(ul.data);
    } catch (e) {
      if (e?.response?.status === 401) nav("/");
    }
  }, [inboxSearch, inboxDateFrom, inboxDateTo, sentSearch, sentDateFrom, sentDateTo, nav]);

  useEffect(() => { load(); }, [load]);

  // Poll unread count every 30s
  useEffect(() => {
    const t = setInterval(async () => {
      try {
        const res = await api.get("/messages/unread-count");
        setUnread(res.data.count);
      } catch {}
    }, 30000);
    return () => clearInterval(t);
  }, []);

  const doSend = async () => {
    if (!compose.recipient) { toast.error("Recipient is required"); return; }
    if (!compose.body) { toast.error("Message body is required"); return; }
    try {
      const res = await api.post("/messages/send", { recipient: compose.recipient, body: compose.body, metadata: compose.metadata || undefined, reply_to: compose.reply_to || undefined });
      toast.success("Message sent and signed");
      setSelectedXml(res.data.xml);
      setCompose({ recipient: compose.recipient, body: "", metadata: "", reply_to: null });
      setReplyLabel(null);
      await load();
    } catch (e) {
      toast.error(e?.response?.data?.detail || "Failed to send");
    }
  };

  const viewXml = async (id) => {
    const res = await api.get(`/messages/${id}`);
    setSelectedXml(res.data.xml);
    await load(); // refresh read status
  };

  const decryptMsg = async (id) => {
    try {
      const res = await api.post(`/messages/${id}/decrypt`);
      setDecrypted(res.data);
      await load();
    } catch {
      toast.error("Decrypt failed");
    }
  };

  const deleteMsg = async (id) => {
    if (!window.confirm("Delete this message?")) return;
    try {
      await api.delete(`/messages/${id}`);
      toast.success("Message deleted");
      await load();
    } catch {
      toast.error("Delete failed");
    }
  };

  const replyTo = (m) => {
    setCompose(c => ({ ...c, recipient: m.sender === me?.username ? m.recipient : m.sender, reply_to: m.id }));
    setReplyLabel(`Replying to message from ${m.sender}`);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const clearReply = () => {
    setCompose(c => ({ ...c, reply_to: null }));
    setReplyLabel(null);
  };

  const logout = async () => {
    await api.post("/auth/logout");
    await refresh();
    nav("/");
  };

  if (!me) return (
    <div className="min-h-screen flex items-center justify-center">
      <Button onClick={() => nav("/")} data-testid="back-to-login">Back to login</Button>
    </div>
  );

  return (
    <div className="min-h-screen bg-gradient-to-b from-emerald-50 via-white to-teal-50">
      <div className="max-w-6xl mx-auto px-6 py-10 space-y-6">

        {/* Header */}
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div>
            <h2 className="font-['Space_Grotesk'] text-3xl font-semibold text-slate-800 flex items-center gap-3" data-testid="welcome-text">
              Welcome, {me.username}
              {unread > 0 && <Badge className="bg-emerald-600 text-white">{unread} unread</Badge>}
            </h2>
            <p className="text-slate-600">Compose messages and review your inbox.</p>
          </div>
          <div className="flex gap-3 items-center flex-wrap">
            <a href={`${API}/messages/schema`} target="_blank" rel="noreferrer" className="text-sm text-teal-700 underline" data-testid="download-xsd">Download XSD</a>
            <Button variant="outline" onClick={() => nav("/profile")} className="rounded-full">⚙ Profile</Button>
            <Button onClick={logout} className="bg-slate-800 hover:bg-slate-900 text-white rounded-full" data-testid="logout-button">Logout</Button>
          </div>
        </div>

        {/* Compose + XML Preview */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <Card className="border-0 shadow-xl ring-1 ring-slate-100/70" data-testid="compose-card">
            <CardHeader>
              <CardTitle>Compose</CardTitle>
              <CardDescription>AES-256-CBC encrypted · RSA-SHA256 signed</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {replyLabel && (
                <div className="flex items-center justify-between bg-emerald-50 border border-emerald-200 rounded-md px-3 py-2 text-sm text-emerald-800">
                  <span>↩ {replyLabel}</span>
                  <button onClick={clearReply} className="text-emerald-600 hover:text-emerald-800 ml-2 font-bold">✕</button>
                </div>
              )}
              <div>
                <Label>Recipient</Label>
                <div className="flex gap-2 mt-1">
                  <Input data-testid="compose-recipient-input" value={compose.recipient} onChange={e => setCompose({ ...compose, recipient: e.target.value })} placeholder="username" list="users-list" />
                  <datalist id="users-list">{users.map(u => <option key={u} value={u} />)}</datalist>
                </div>
              </div>
              <div>
                <Label>Body</Label>
                <Textarea data-testid="compose-body-textarea" rows={5} value={compose.body} onChange={e => setCompose({ ...compose, body: e.target.value })} placeholder="Write your message…" />
              </div>
              <div>
                <Label>Metadata <span className="text-slate-400 text-xs">(optional)</span></Label>
                <Input data-testid="compose-metadata-input" value={compose.metadata} onChange={e => setCompose({ ...compose, metadata: e.target.value })} placeholder="key=value;example=true" />
              </div>
              <Button onClick={doSend} className="bg-emerald-600 hover:bg-emerald-700 text-white rounded-full w-full" data-testid="compose-send-button">
                {compose.reply_to ? "↩ Send Reply" : "Send Message"}
              </Button>
            </CardContent>
          </Card>

          <Card className="border-0 shadow-xl ring-1 ring-slate-100/70" data-testid="preview-card">
            <CardHeader>
              <CardTitle>XML Preview</CardTitle>
              <CardDescription>Validated against XSD before save.</CardDescription>
            </CardHeader>
            <CardContent>
              <pre data-testid="xml-preview" className="bg-slate-900 text-slate-100 p-4 rounded-lg overflow-auto max-h-96 text-xs">
                {selectedXml || "Send a message to preview the XML here."}
              </pre>
            </CardContent>
          </Card>
        </div>

        {/* Inbox + Sent */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Inbox */}
          <Card className="border-0 shadow-xl ring-1 ring-slate-100/70" data-testid="inbox-card">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                Inbox
                {unread > 0 && <Badge className="bg-emerald-600 text-white text-xs">{unread}</Badge>}
              </CardTitle>
              <CardDescription>Encrypted + signed messages to you</CardDescription>
            </CardHeader>
            <CardContent>
              <SearchBar value={inboxSearch} dateFrom={inboxDateFrom} dateTo={inboxDateTo} onChange={setInboxSearch} onDateFrom={setInboxDateFrom} onDateTo={setInboxDateTo} placeholder="Search by sender…" />
              <ul className="space-y-2 max-h-96 overflow-y-auto pr-1">
                {inbox.length === 0 && <li className="text-slate-400 text-sm text-center py-6">No messages</li>}
                {inbox.map(m => (
                  <MsgRow key={m.id} m={m} isInbox={true} onViewXml={viewXml} onDecrypt={decryptMsg} onDelete={deleteMsg} onReply={replyTo} />
                ))}
              </ul>
            </CardContent>
          </Card>

          {/* Sent */}
          <Card className="border-0 shadow-xl ring-1 ring-slate-100/70" data-testid="sent-card">
            <CardHeader>
              <CardTitle>Sent</CardTitle>
              <CardDescription>Your outbound messages</CardDescription>
            </CardHeader>
            <CardContent>
              <SearchBar value={sentSearch} dateFrom={sentDateFrom} dateTo={sentDateTo} onChange={setSentSearch} onDateFrom={setSentDateFrom} onDateTo={setSentDateTo} placeholder="Search by recipient…" />
              <ul className="space-y-2 max-h-96 overflow-y-auto pr-1">
                {sent.length === 0 && <li className="text-slate-400 text-sm text-center py-6">No sent messages</li>}
                {sent.map(m => (
                  <MsgRow key={m.id} m={m} isInbox={false} onViewXml={viewXml} onDecrypt={decryptMsg} onDelete={deleteMsg} onReply={replyTo} />
                ))}
              </ul>
            </CardContent>
          </Card>
        </div>

        {/* Decrypted panel */}
        {decrypted && (
          <Card className="border-0 shadow-2xl ring-1 ring-emerald-200" data-testid="decrypt-panel">
            <CardHeader>
              <CardTitle>Decrypted Message</CardTitle>
              <CardDescription>Message ID: {decrypted.id}</CardDescription>
            </CardHeader>
            <CardContent>
              <pre className="bg-emerald-50 text-slate-800 p-4 rounded-lg overflow-auto">{decrypted.plaintext}</pre>
              <div className="mt-4 flex gap-2">
                <Button onClick={() => setDecrypted(null)} className="rounded-full" data-testid="close-decrypt-panel">Close</Button>
              </div>
            </CardContent>
          </Card>
        )}
      </div>
      <Toaster position="top-right" richColors />
    </div>
  );
}

// ─── App ───────────────────────────────────────────────────────────────────────
function App() {
  return (
    <div className="min-h-screen">
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<AuthPage />} />
          <Route path="/messages" element={<MessagesPage />} />
          <Route path="/profile" element={<ProfilePage />} />
        </Routes>
      </BrowserRouter>
    </div>
  );
}

export default App;
