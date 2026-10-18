'use strict';
// Keep accessible names when navigation labels are hidden.
for(const item of document.querySelectorAll('.sidebar .nav')){
 const label=item.textContent.trim();item.setAttribute('aria-label',label);item.title=label;
 for(const node of [...item.childNodes])if(node.nodeType===Node.TEXT_NODE&&node.textContent.trim()){
  const span=document.createElement('span');span.className='nav-label';span.textContent=node.textContent;node.replaceWith(span);
 }
}
function setMenuCollapsed(collapsed){
 document.documentElement.classList.toggle('menu-collapsed',collapsed);
 $('sidebar-toggle').setAttribute('aria-expanded',String(!collapsed));
 $('sidebar-toggle').setAttribute('aria-label',collapsed?'Expandir menú':'Contraer menú');
 $('sidebar-toggle').title=collapsed?'Expandir menú':'Contraer menú';
 try{localStorage.setItem('mk-menu-collapsed',collapsed?'1':'0');}catch{}
}
try{setMenuCollapsed(localStorage.getItem('mk-menu-collapsed')==='1');}catch{setMenuCollapsed(false);}
$('sidebar-toggle').onclick=()=>setMenuCollapsed(!document.documentElement.classList.contains('menu-collapsed'));
function expiryTime(value){return value?new Date(value*1000).toLocaleString('es-MX'):'Sin vencimiento';}
function expirationSummary(user){
 const p=user.expiration;
 if(!p)return user.windows_expires_at?`<small class="expiry-note">Windows: ${esc(expiryTime(user.windows_expires_at))}</small>`:'';
 const names={pending:'Solicitud pendiente',armed:'Programado',done:'Vencimiento procesado',cancelled:'Sin vencimiento',conflict:'Revisar cambio externo'};
 return `<small class="expiry-note">${esc(names[p.state]||p.state)}${p.expires_at?' · '+esc(expiryTime(p.expires_at)):''}</small>${p.error?`<small class="expiry-note error">${esc(p.error)}</small>`:''}${p.alert_status?`<small class="expiry-note">Alerta: ${esc({pending:'pendiente de entrega',sent:'entregada',simulated:'simulada'}[p.alert_status]||p.alert_status)}</small>`:''}`;
}
function configureExpiration(user){
 const p=user.expiration;const stamp=p&&p.state!=='cancelled'?p.expires_at:user.windows_expires_at;
 let input='';if(stamp){const d=new Date(stamp*1000);input=new Date(d.getTime()-d.getTimezoneOffset()*60000).toISOString().slice(0,16);}
 const zone=Intl.DateTimeFormat().resolvedOptions().timeZone;
 modal('Vencimiento de cuenta',`<p>Usuario: <strong>${esc(user.username)}</strong></p><label for="account-deadline">Fecha y hora de vencimiento</label><input id="account-deadline" name="deadline" type="datetime-local" value="${esc(input)}"><p class="helper">Zona de esta sesión: ${esc(zone)}. Deja la fecha vacía para retirar el vencimiento.</p><div class="notice">Windows impedirá nuevos inicios de sesión al vencer. Metakampo confirmará la deshabilitación y enviará una alerta al Telegram existente. Las sesiones abiertas no se cierran. El propietario debe estar abierto para procesar la deshabilitación y los avisos.</div>${p?.error?`<p class="error">${esc(p.error)}</p>`:''}<p class="helper">Ampliar o retirar la fecha no reactiva una cuenta deshabilitada. Después puedes activarla desde Gestionar.</p><label for="expiry-password">Tu contraseña de Metakampo</label><input id="expiry-password" name="admin_password" type="password" autocomplete="current-password" required>`,'Guardar vencimiento',async data=>{
  const value=data.deadline?new Date(data.deadline):null;
  if(value&&(!Number.isFinite(value.getTime())||value.getTime()<=Date.now()))throw new Error('Elige una fecha y hora futuras o deja el campo vacío.');
  await api('users/'+user.id+'/expiration',{expires_at:value?value.toISOString():null,admin_password:data.admin_password});
  closeModal();await loadUsers();toast('Vencimiento guardado. La fecha no reactiva cuentas deshabilitadas.');
 });
}
document.addEventListener('click',e=>{const button=e.target.closest('[data-expiration]');if(!button)return;const user=state.users.find(u=>u.id===button.dataset.expiration);if(user&&!user.protected)configureExpiration(user);});
$('expiry-history').onclick=async()=>{
 try{
  const data=await api('account-expiry');
  const names={pending:'Pendiente',sent:'Entregada',simulated:'Simulada'};
  modal('Vencimientos y alertas',`<p>Últimas 100 acciones y alertas. ${data.demo?'Datos simulados; no se modifica Windows ni se envía a Telegram.':'Se registra el resultado confirmado de Windows.'}</p><h3>Alertas de usuario deshabilitado</h3><div class="table-scroll"><table><thead><tr><th>Usuario</th><th>Confirmado</th><th>Telegram</th></tr></thead><tbody>${data.alerts.map(a=>`<tr><td>${esc(a.username)}</td><td>${esc(expiryTime(a.verified_at))}</td><td>${esc(names[a.status]||a.status)}${a.error?`<small class="expiry-note">${esc(a.error)}</small>`:''}</td></tr>`).join('')||'<tr><td colspan="3" class="empty">Sin alertas de vencimiento.</td></tr>'}</tbody></table></div><h3>Actividad</h3><div class="table-scroll"><table><thead><tr><th>Usuario</th><th>Acción</th><th>Resultado</th></tr></thead><tbody>${data.history.map(h=>`<tr><td>${esc(h.username)}<small class="expiry-note">${esc(expiryTime(h.at))} · ${esc(h.actor)}</small></td><td>${esc(h.action)}</td><td>${esc(h.result)}</td></tr>`).join('')||'<tr><td colspan="3" class="empty">Sin programaciones registradas.</td></tr>'}</tbody></table></div>`,null,null);
 }catch(e){error(e.message);}
};
