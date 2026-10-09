const $ = s => document.querySelector(s);
const esc = v => String(v ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const A = "Admin", D = "Dispatcher", R = "Driver", V = "Viewer";
let token = sessionStorage.getItem("t"), me = null, tab = "dashboard";

async function api(path, method = "GET", body) {
  const r = await fetch("/api" + path, { method, headers: { "Content-Type": "application/json", ...(token ? { Authorization: "Bearer " + token } : {}) }, body: body ? JSON.stringify(body) : undefined });
  const d = await r.json().catch(() => ({}));
  if (r.status === 401 && token) { logout(); }
  if (!r.ok) throw new Error(d.error || "Request failed");
  return d;
}
function say(t, ok) { const m = $("#msg"); m.textContent = t; m.className = ok ? "good" : "err"; m.style.display = "block"; setTimeout(() => m.style.display = "none", 5000); }
function logout() { token = null; me = null; sessionStorage.removeItem("t"); $("#login").hidden = false; $("#nav").hidden = $("#main").hidden = true; $("#who").textContent = ""; }

// tab config: roles = who sees it, list = who can load the table, form = who can add
const TABS = {
  dashboard: { roles: [A, D, V] },
  vehicles: { roles: [A, D, V], list: [A, D, V], path: "/vehicles", cols: ["plate_no", "make", "model", "year", "status", "odometer"], form: { roles: [A, D], f: [["plate_no"], ["make"], ["model"], ["year", "number"], ["odometer", "number"]] } },
  drivers: { roles: [A, D, V], list: [A, D, V], path: "/drivers", cols: ["name", "license_no", "license_expiry", "contact"], form: { roles: [A, D], f: [["name"], ["license_no"], ["license_expiry", "date"], ["contact"]] } },
  trips: { roles: [A, D, R, V], list: [A, D, R, V], path: "/trips", cols: ["id", "plate_no", "driver_name", "origin", "destination", "status", "distance"], form: { roles: [A, D], f: [["vehicle_id", "number"], ["driver_id", "number"], ["origin"], ["destination"]] }, done: [A, D, R] },
  maintenance: { roles: [A, D, V], list: [A, D, V], path: "/maintenance", cols: ["plate_no", "type", "date", "cost", "odometer"], form: { roles: [A, D], f: [["vehicle_id", "number"], ["type"], ["date", "date"], ["cost", "number"]] } },
  fuel: { roles: [A, D, R, V], list: [A, D, V], path: "/fuel", cols: ["plate_no", "date", "liters", "cost", "odometer"], form: { roles: [A, D, R], f: [["vehicle_id", "number"], ["date", "date"], ["liters", "number"], ["cost", "number"], ["odometer", "number"]] } },
  users: { roles: [A], list: [A], path: "/users", cols: ["id", "username", "role", "active"], form: { roles: [A], f: [["username"], ["password", "password"], ["role", "select"]] }, toggle: true },
  audit: { roles: [A], list: [A], path: "/audit", cols: ["ts", "user", "action", "detail", "ip"] },
};

function nav() {
  $("#nav").innerHTML = Object.keys(TABS).filter(t => TABS[t].roles.includes(me.role)).map(t => `<button data-t="${t}" class="${t === tab ? "on" : ""}">${t[0].toUpperCase() + t.slice(1)}</button>`).join("");
  $("#nav").hidden = $("#main").hidden = false; $("#login").hidden = true;
  $("#who").innerHTML = `${esc(me.username)} <span class="tag">${esc(me.role)}</span> <button class="s" id="out">Sign out</button>`;
}
$("#nav").onclick = e => { if (e.target.dataset.t) { tab = e.target.dataset.t; nav(); render(); } };
$("#who").onclick = e => { if (e.target.id === "out") logout(); };

async function render() {
  const T = TABS[tab], m = $("#main");
  try {
    if (tab === "dashboard") {
      const [d, a] = await Promise.all([api("/dashboard"), api("/alerts")]);
      const st = d.vehicles;
      m.innerHTML = `<div class="grid">${[["Active trips", d.active_trips], ["Available", st.Available || 0], ["In use", st["In Use"] || 0], ["In maintenance", st.Maintenance || 0], ["Fuel cost", d.fuel_cost], ["Maintenance cost", d.maintenance_cost]].map(([l, v]) => `<div class="card"><div class="mut">${l}</div><div class="k">${esc(v)}</div></div>`).join("")}</div>
      <div class="card"><b>Alerts (${d.alerts})</b>${a.maintenance.map(v => `<p class="warn">🔧 ${esc(v.plate_no)} is due for service (odometer ${esc(v.odometer)})</p>`).join("")}${a.licenses.map(x => `<p class="warn">🪪 ${esc(x.name)} licence expires ${esc(x.license_expiry)}</p>`).join("") || ""}${d.alerts ? "" : '<p class="mut">No alerts.</p>'}</div>`;
      return;
    }
    let html = "";
    if (T.form && T.form.roles.includes(me.role)) {
      html += `<div class="card"><b>Add</b><br>${T.form.f.map(([k, t, o]) => t === "select" ? `<select name="${k}">${["Admin", "Dispatcher", "Driver", "Viewer"].map(r => `<option>${r}</option>`).join("")}</select>` : `<input name="${k}" type="${t || "text"}" placeholder="${k}" ${t === "number" ? 'step="any"' : ""}>`).join("")}<button class="p" id="add">Save</button></div>`;
    }
    if (T.list.includes(me.role)) {
      const rows = await api(T.path);
      html += `<div class="card"><table><tr>${T.cols.map(c => `<th>${esc(c)}</th>`).join("")}<th></th></tr>${rows.map(r => `<tr>${T.cols.map(c => `<td>${esc(r[c])}</td>`).join("")}<td>${T.done && T.done.includes(me.role) && r.status === "Active" ? `<button class="s" data-done="${r.id}">Complete</button>` : ""}${T.toggle ? `<button class="s" data-tog="${r.id}">${r.active ? "Disable" : "Enable"}</button>` : ""}</td></tr>`).join("")}</table>${rows.length ? "" : '<p class="mut">No records.</p>'}</div>`;
    } else html += '<p class="mut">You can add records here but not view the full list.</p>';
    m.innerHTML = html;
  } catch (e) { say(e.message); }
}

$("#main").onclick = async e => {
  const T = TABS[tab];
  try {
    if (e.target.id === "add") {
      const b = {}; document.querySelectorAll("#main [name]").forEach(i => b[i.name] = i.type === "number" ? (i.value === "" ? null : Number(i.value)) : i.value);
      await api(T.path, "POST", b); say("Saved", true); render();
    } else if (e.target.dataset.done) {
      const odo = prompt("End odometer reading:"); if (odo === null) return;
      const r = await api(`/trips/${e.target.dataset.done}/complete`, "POST", { end_odometer: Number(odo) });
      say(`Trip completed, ${r.distance} km${r.maintenance_due ? " - vehicle is DUE for maintenance" : ""}`, true); render();
    } else if (e.target.dataset.tog) { await api(`/users/${e.target.dataset.tog}/toggle`, "POST"); render(); }
  } catch (err) { say(err.message); }
};

$("#go").onclick = async () => {
  try {
    const r = await api("/login", "POST", { username: $("#u").value, password: $("#p").value });
    token = r.token; sessionStorage.setItem("t", token); $("#p").value = ""; me = r.user; tab = "dashboard"; nav(); render();
  } catch (e) { say(e.message); }
};
$("#p").onkeydown = e => { if (e.key === "Enter") $("#go").click(); };
if (token) api("/me").then(u => { me = u; nav(); render(); }).catch(logout);
