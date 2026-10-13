'use strict';
const $ = id => document.getElementById(id);
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const icon = name => `<svg class="icon" aria-hidden="true"><use href="/static/icons.svg#${name}"></use></svg>`;
const state = {csrf:'', users:[], view:'dashboard', secretTimer:null, rdpDemo:true, desktop:false};
const pages = {
 dashboard:['Dashboard de uso','Accesos observados en Windows, usuarios y servidores en un solo lugar.',null],
 users:['Directorio de usuarios','Gestiona cuentas y accesos de tu organización.','Nuevo usuario'],
 vault:['Bóveda de contraseñas','Credenciales protegidas, disponibles cuando las necesitas.','Nueva credencial'],
 rdp:['Clientes RDP','Distribuye conexiones firmadas con credenciales preparadas para Windows.','Generar cliente RDP'],
 policy:['Política de seguridad','Define el estándar para las contraseñas de tu organización.',null],
 audit:['Registro de actividad','Cada acción deja una referencia para tu equipo de TI.',null]
};
let modalHandler = null;
function hydrateIcons(root=document){root.querySelectorAll('[data-icon]').forEach(el=>el.innerHTML=icon(el.dataset.icon+(el.closest('.nav.active')?'-solid':'')));}
function toast(message){$('toast').textContent=message;$('toast').hidden=false;setTimeout(()=>$('toast').hidden=true,4000);}
async function api(path,body){
 const options={credentials:'same-origin',headers:{'X-CSRF-Token':state.csrf}};
 if(body!==undefined){options.method='POST';options.headers['Content-Type']='application/json';options.body=JSON.stringify(body);}
 let response;
 try{response=await fetch('/api/'+path,options);}catch{throw new Error('Sin conexión con el servidor. Verifica la conexión y vuelve a intentar.');}
 const data=await response.json().catch(()=>({error:'El servidor no pudo completar la solicitud.'}));
 if(!response.ok){
   if(response.status===401 && path!=='login'){showLogin();clearSecret();}
   throw new Error(data.error||'No se pudo completar la operación.');
 }
 return data;
}
function busy(button,value){if(button){button.disabled=value;button.setAttribute('aria-busy',String(value));}}
function error(message){$('page-error').textContent='Error: '+message;$('page-error').hidden=false;}
function showLogin(){if($('modal').open)closeModal();clearSecret();$('workspace').hidden=true;$('login-screen').hidden=false;$('login-password').value='';}
async function openWorkspace(){
 $('login-screen').hidden=true;$('workspace').hidden=false;$('page-error').hidden=true;
 await navigate('dashboard');
}
async function navigate(view){
 if(!pages[view])return;
 state.view=view;$('page-error').hidden=true;
 document.querySelectorAll('.view').forEach(el=>el.hidden=el.id!==view+'-view');
 document.querySelectorAll('.nav[data-view]').forEach(el=>{el.classList.toggle('active',el.dataset.view===view);el.setAttribute('aria-current',el.dataset.view===view?'page':'false');const symbol=el.querySelector('[data-icon]');if(symbol)symbol.innerHTML=icon(symbol.dataset.icon+(el.dataset.view===view?'-solid':''));});
 const [title,description,action]=pages[view];$('page-title').textContent=title;$('crumb').textContent=title;$('page-description').textContent=description;
 $('page-action').hidden=!action;$('page-action').innerHTML=icon('plus')+esc(action||'');
 try{
  if(view==='users'){await Promise.all([loadUsers(),loadPolicy()]);}
  if(view==='vault')await loadVault();
  if(view==='policy')await loadPolicy();
  if(view==='audit')await loadAudit();
  if(view==='rdp')await loadRdp();
  if(view==='dashboard')await loadDashboard();
 }catch(e){error(e.message);}
}
async function loadPolicy(){const data=await api('policy');$('length').value=data.length;$('policy-length').textContent=data.length;$('generator-length').textContent=data.length+' caracteres';}
async function loadUsers(){
 $('users-body').innerHTML='<tr><td colspan="4" class="empty" aria-live="polite">Consultando el directorio…</td></tr>';
 busy($('refresh-users'),true);
 try{
  state.users=(await api('users')).users;
  $('total-users').textContent=state.users.length;$('active-users').textContent=state.users.filter(u=>u.enabled).length;$('disabled-users').textContent=state.users.filter(u=>!u.enabled).length;
  renderUsers();
 }catch(e){$('users-body').innerHTML='<tr><td colspan="4" class="empty">No se pudo consultar el directorio. Usa Actualizar para reintentar.</td></tr>';throw e;}
 finally{busy($('refresh-users'),false);}
}
function renderUsers(){
 const query=$('search').value.toLocaleLowerCase('es');const status=$('status-filter').value;
 const values=state.users.filter(u=>[u.name,u.username,u.department].join(' ').toLocaleLowerCase('es').includes(query)&&(status==='all'||Boolean(u.enabled)===(status==='active')));
 $('users-body').innerHTML=values.map(u=>`<tr><td><div class="user-cell"><span class="avatar" aria-hidden="true">${esc(u.name.split(' ').filter(Boolean).slice(0,2).map(n=>n[0]).join(''))}</span><div><strong>${esc(u.name)}</strong><small>${esc(u.username)}</small></div></div></td><td>${esc(u.department||'Sin departamento')}</td><td><span class="badge ${u.enabled?'active':''}">${u.enabled?'Activo':'Deshabilitado'}</span></td><td><div class="row-actions"><button class="icon-button" data-rdp-user="${esc(u.id)}" aria-label="Generar cliente RDP para ${esc(u.name)}" title="Generar cliente RDP">${icon('computer')}</button><button class="icon-button" data-action="reset" data-id="${esc(u.id)}" aria-label="Restablecer contraseña de ${esc(u.name)}" title="Restablecer contraseña">${icon('key')}</button><button class="icon-button" data-action="${u.enabled?'disable':'enable'}" data-id="${esc(u.id)}" aria-label="${u.enabled?'Deshabilitar':'Habilitar'} a ${esc(u.name)}" title="${u.enabled?'Deshabilitar':'Habilitar'} cuenta">${icon(u.enabled?'disable':'check')}</button>${u.locked?`<button class="icon-button" data-action="unlock" data-id="${esc(u.id)}" aria-label="Desbloquear a ${esc(u.name)}">${icon('unlock')}</button>`:''}</div></td></tr>`).join('')||'<tr><td colspan="4" class="empty">No hay usuarios que coincidan con tu búsqueda.</td></tr>';
 $('user-count').textContent=`${values.length} de ${state.users.length} usuarios`;
}
async function loadVault(){
 $('vault-list').innerHTML='<div class="empty">Cargando credenciales…</div>';
 const values=(await api('vault')).entries;
 $('vault-list').innerHTML=values.map(e=>`<article class="card vault-card"><div class="icon-box">${icon('lock')}</div><h2>${esc(e.title)}</h2><p>${esc(e.username)}</p><span class="badge">AES-256-GCM</span><button class="secondary" data-reveal="${esc(e.id)}" data-title="${esc(e.title)}">${icon('eye')}Consultar contraseña</button></article>`).join('')||'<div class="empty"><h2>Tu bóveda está lista</h2><p>Agrega una credencial para generar y guardar una contraseña cifrada.</p><button class="primary" data-new-vault>Nueva credencial</button></div>';
}
async function loadAudit(){
 $('audit-body').innerHTML='<tr><td colspan="5" class="empty">Cargando actividad…</td></tr>';
 const values=(await api('audit')).events;
 $('audit-body').innerHTML=values.map(e=>`<tr><td>${esc(new Date(e.at.replace(' ','T')+'Z').toLocaleString('es-MX'))}</td><td>${esc(e.actor)}</td><td>${esc(e.action)}</td><td>${esc(e.target||'—')}</td><td><span class="badge">${esc(e.result)}</span></td></tr>`).join('')||'<tr><td colspan="5" class="empty">Aún no hay actividad registrada.</td></tr>';
}
function clearSecret(){clearTimeout(state.secretTimer);const node=$('secret-value');if(node)node.textContent='La contraseña se ha ocultado.';const copy=$('copy-secret');if(copy)copy.disabled=true;}
function closeModal(){clearSecret();$('modal').close();$('modal-body').replaceChildren();modalHandler=null;}
function modal(title,html,submitLabel,handler){
 clearSecret();$('modal-title').textContent=title;$('modal-body').innerHTML=html;$('modal-error').textContent='';$('modal-submit').hidden=!handler;$('modal-submit').textContent=submitLabel||'Guardar';$('cancel-modal').textContent=handler?'Cancelar':'Cerrar';busy($('modal-submit'),false);modalHandler=handler;$('modal').showModal();
 const first=$('modal-body').querySelector('input');if(first)first.focus();
}
function showSecret(value,title='Contraseña generada'){
 modal(title,`<p>Guárdala o entrégala por un canal seguro. Se ocultará en 60 segundos.</p><div id="secret-value" class="secret-box"></div><button type="button" id="copy-secret" class="secondary wide">Copiar contraseña</button><p class="helper">El portapapeles conserva lo copiado hasta que lo sustituyas.</p>`,null,null);
 $('secret-value').textContent=value;
 $('copy-secret').onclick=async()=>{try{await navigator.clipboard.writeText($('secret-value').textContent);toast('Contraseña copiada.');}catch{$('modal-error').textContent='No fue posible copiar. Selecciona la contraseña y cópiala manualmente.';}};
 state.secretTimer=setTimeout(clearSecret,60000);
}
function createUser(){modal('Nuevo usuario','<p>Se generará una contraseña con la política vigente.</p><label for="new-name">Nombre completo</label><input id="new-name" name="name" maxlength="120" autocomplete="off" required><label for="new-username">Usuario de dominio</label><input id="new-username" name="username" maxlength="20" pattern="[a-zA-Z0-9._-]{1,20}" autocomplete="off" required><p class="helper">Ejemplo: nombre.apellido</p><label for="new-department">Departamento</label><input id="new-department" name="department" maxlength="120" required><div class="notice">La cuenta se creará en la OU autorizada. Debe cambiar la contraseña al iniciar sesión.</div>','Crear usuario',async data=>{
 const result=await api('users',data);await loadUsers();showSecret(result.password,'Contraseña inicial');toast('Usuario creado.');
 });}
function createVault(){modal('Nueva credencial','<p>Genera una clave y guárdala cifrada. Debes aplicarla al sistema correspondiente por separado.</p><label for="vault-title">Nombre de la credencial</label><input id="vault-title" name="title" maxlength="120" required placeholder="Ej. cuenta de servicio"><label for="vault-user">Usuario o cuenta</label><input id="vault-user" name="username" maxlength="120" required>','Generar y guardar',async data=>{const result=await api('vault',data);await loadVault();showSecret(result.password,'Credencial guardada');});}
$('modal-form').onsubmit=async e=>{e.preventDefault();if(!modalHandler)return;const action=modalHandler;busy($('modal-submit'),true);$('modal-error').textContent='';try{await action(Object.fromEntries(new FormData(e.target)));}catch(err){$('modal-error').textContent='Error: '+err.message;}finally{busy($('modal-submit'),false);}};
$('close-modal').onclick=closeModal;$('cancel-modal').onclick=closeModal;$('modal').addEventListener('cancel',e=>{e.preventDefault();closeModal();});
document.addEventListener('visibilitychange',()=>{if(document.hidden)clearSecret();});
document.addEventListener('click',async e=>{
 const nav=e.target.closest('[data-view]');if(nav){await navigate(nav.dataset.view);return;}
 const collector=e.target.closest('[data-revoke-collector]');if(collector){modal('Revocar recolector','<p>Este servidor dejará de enviar nuevos eventos. El historial ya recibido se conserva.</p><label for="collector-confirm">Contraseña de administrador</label><input id="collector-confirm" name="admin_password" type="password" autocomplete="current-password" required>','Revocar',async data=>{await api('collectors/'+collector.dataset.revokeCollector+'/revoke',data);closeModal();await loadDashboard();});return;}
 const rdpUser=e.target.closest('[data-rdp-user]');if(rdpUser){createRdp(state.users.find(u=>u.id===rdpUser.dataset.rdpUser));return;}
 const revoke=e.target.closest('[data-revoke-rdp]');if(revoke){modal('Revocar activación RDP','<p>El destinatario ya no podrá activar este paquete. Esta acción no elimina credenciales que ya estén guardadas en Windows.</p>','Revocar',async()=>{await api('rdp/clients/'+revoke.dataset.revokeRdp+'/revoke',{});closeModal();await loadRdp();toast('Activación revocada.');});return;}
 const newVault=e.target.closest('[data-new-vault]');if(newVault){createVault();return;}
 const reveal=e.target.closest('[data-reveal]');if(reveal){modal('Consultar '+reveal.dataset.title,'<p>Confirma tu identidad para acceder a esta credencial.</p><label for="confirm-password">Contraseña de administrador</label><input id="confirm-password" name="password" type="password" autocomplete="current-password" required>','Consultar',async data=>{const result=await api('vault/'+reveal.dataset.reveal+'/reveal',data);showSecret(result.password,'Credencial consultada');});return;}
 const action=e.target.closest('[data-action]');if(action){const user=state.users.find(u=>u.id===action.dataset.id);if(!user)return;const type=action.dataset.action;const labels={reset:'Restablecer contraseña',disable:'Deshabilitar cuenta',enable:'Habilitar cuenta',unlock:'Desbloquear cuenta'};
 modal(labels[type],`<p>Cuenta: <strong>${esc(user.name)}</strong> (${esc(user.username)}).</p><p>${type==='reset'?'Se reemplazará la contraseña actual y se solicitará un cambio al iniciar sesión.':type==='disable'?'La cuenta perderá el acceso de inicio de sesión.':'Se actualizará el estado de la cuenta.'}</p>`,'Confirmar',async()=>{const result=await api('users/'+user.id+'/'+type,{});await loadUsers();if(result.password)showSecret(result.password,'Nueva contraseña de '+user.username);else{closeModal();toast('Cuenta actualizada.');}});
 }
});
$('page-action').onclick=()=>state.view==='users'?createUser():state.view==='rdp'?createRdp():createVault();
$('search').oninput=renderUsers;$('status-filter').onchange=renderUsers;
$('refresh-users').onclick=async()=>{try{await loadUsers();$('page-error').hidden=true;}catch(e){error(e.message);}};
$('refresh-audit').onclick=async()=>{try{await loadAudit();}catch(e){error(e.message);}};
$('generate').onclick=async()=>{busy($('generate'),true);try{showSecret((await api('generate',{})).password);}catch(e){error(e.message);}finally{busy($('generate'),false);}};
$('policy-form').onsubmit=async e=>{e.preventDefault();const button=e.target.querySelector('button');busy(button,true);try{await api('policy',{length:Number($('length').value)});await loadPolicy();toast('Política actualizada.');}catch(err){error(err.message);}finally{busy(button,false);}};
$('login-form').onsubmit=async e=>{e.preventDefault();const button=e.target.querySelector('button');busy(button,true);$('login-error').textContent='';try{const result=await api('login',Object.fromEntries(new FormData(e.target)));state.csrf=result.csrf;$('login-password').value='';await openWorkspace();}catch(err){$('login-error').textContent='Error: '+err.message;}finally{busy(button,false);}};
$('logout').onclick=async()=>{try{await api('logout',{});showLogin();state.csrf=(await api('session')).csrf;}catch(e){error(e.message);}};
$('theme-toggle').onclick=()=>{const mode=document.documentElement.dataset.mode==='dark'?'light':'dark';document.documentElement.dataset.mode=mode;localStorage.setItem('fk-mode',mode);};

async function loadRdp(){
 const status=await api('rdp/status');state.rdpDemo=status.demo;
 $('rdp-state').textContent=status.demo?'Vista previa sin firma':status.configured?'Configuración disponible':'Configuración pendiente';
 $('rdp-signing-note').textContent=status.desktop&&!status.demo?status.message:status.demo?'En demostración se descarga únicamente un perfil sin firma ni contraseña. La firma real se realiza en Windows Server.':status.configured?'La firma y el acceso a las claves privadas se validan al generar cada paquete.':'Configura el certificado, la clave privada y el origen HTTPS del portal en Windows Server.';
 $('rdp-clients').innerHTML='<tr><td colspan="5" class="empty">Consultando activaciones…</td></tr>';
 const clients=(await api('rdp/clients')).clients;
 $('rdp-clients').innerHTML=clients.map(c=>`<tr><td>${esc(c.host)}</td><td>${esc(c.username)}</td><td>${esc(new Date((state.desktop?c.created.replace(' ','T')+'Z':c.expires*1000)).toLocaleString('es-MX'))}</td><td><span class="badge">${esc(state.desktop&&c.status==='activado'?'Preparado para este servidor':c.status)}</span></td><td>${c.status==='pendiente'?`<button class="secondary" data-revoke-rdp="${esc(c.id)}">Revocar</button>`:'—'}</td></tr>`).join('')||'<tr><td colspan="5" class="empty">No hay activaciones emitidas. Genera un cliente RDP para comenzar.</td></tr>';
}
async function downloadRdp(data){
 let response;
 try{response=await fetch('/api/rdp/package',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':state.csrf},body:JSON.stringify(data)});}catch{throw new Error('No se pudo conectar con el gestor.');}
 if(!response.ok){const info=await response.json().catch(()=>({}));throw new Error(info.error||'No se pudo generar el cliente RDP.');}
 const blob=await response.blob();const url=URL.createObjectURL(blob);const link=document.createElement('a');
 const signed=response.headers.get('X-RDP-Signed')==='true';
 link.href=url;link.download=signed?(state.desktop?'Freshkampo-RDP-local-firmado.zip':'Freshkampo-RDP-firmado.zip'):'Freshkampo-RDP-DEMO-sin-firma.zip';document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
 return signed;
}
async function createRdp(user){
 try{
 const info=await api('rdp/status');state.rdpDemo=info.demo;let connection=null;
 const username=user?.upn||('DOMINIO\\'+(user?.username||'usuario'));
 modal(info.demo?'Vista previa de cliente RDP':'Generar cliente RDP firmado',`
 <ol class="form-steps" aria-label="Pasos del formulario"><li id="rdp-step-1" class="current">1 · Conexión</li><li id="rdp-step-2">2 · Credenciales</li></ol>
 <section id="rdp-connection"><label for="rdp-host">Servidor de destino</label><input id="rdp-host" name="host" maxlength="253" placeholder="srv-rdp.empresa.local" autocomplete="off" required><div class="rdp-port-user"><div><label for="rdp-port">Puerto</label><input id="rdp-port" name="port" type="number" value="3389" min="1" max="65535" required></div><div><label for="rdp-user">Cuenta de Windows</label><input id="rdp-user" name="username" value="${esc(username)}" maxlength="253" autocomplete="off" required></div></div><p class="helper">DOMINIO\\usuario o usuario@dominio. La cuenta debe tener permiso para RDP.</p>${info.demo?'<div class="notice">Vista previa sin firma ni contraseña. No se genera una activación.</div>':''}</section>
 <section id="rdp-credentials" hidden><label for="rdp-account-password">Contraseña vigente de la cuenta</label><input id="rdp-account-password" name="account_password" type="password" autocomplete="off" maxlength="256" required disabled><p class="helper">No se restablece ni se cambia la contraseña de AD.</p><label for="rdp-code">Código de activación para el destinatario</label><input id="rdp-code" name="activation_code" type="password" minlength="15" maxlength="128" autocomplete="off" readonly required disabled><p class="helper">Código fuerte generado automáticamente. Se mostrará al descargar el paquete para entregarlo por separado. Caduca en 30 minutos.</p><label for="rdp-admin-password">Confirma tu contraseña de administrador</label><input id="rdp-admin-password" name="admin_password" type="password" autocomplete="current-password" required disabled><div class="notice">La contraseña se guarda cifrada hasta la activación. El lanzador la recibe una sola vez y la guarda en el perfil Windows del destinatario.</div></section>`,info.demo?'Descargar vista previa':'Continuar',async data=>{
 if(!connection){connection={host:data.host,username:data.username,port:Number(data.port)};if(!info.demo){if(!state.desktop){const generated=await api('generate',{});$('rdp-code').value=generated.password;}$('rdp-connection').hidden=true;$('rdp-credentials').hidden=false;$('rdp-connection').querySelectorAll('input').forEach(i=>i.disabled=true);$('rdp-credentials').querySelectorAll('input').forEach(i=>i.disabled=state.desktop&&i.id==='rdp-code');$('rdp-step-1').classList.remove('current');$('rdp-step-2').classList.add('current');$('modal-submit').textContent='Generar y descargar';$('rdp-account-password').focus();return;}}
 const signed=await downloadRdp({...connection,...data,port:connection.port});if(signed&&!state.desktop)showSecret(data.activation_code,'Código de activación RDP');else closeModal();if(state.view==='rdp')await loadRdp();toast(signed?(state.desktop?'Cliente firmado preparado para este servidor y cuenta Windows.':'Cliente firmado descargado. Entrega el código por separado.'):'Vista previa descargada, sin firma ni contraseña.');
 });
 if(state.desktop){const field=$('rdp-code');field.hidden=true;field.required=false;document.querySelector('label[for="rdp-code"]').hidden=true;field.nextElementSibling.hidden=true;$('rdp-credentials').querySelector('.notice').textContent='La contraseña se protegerá con Windows DPAPI para este servidor y la cuenta Windows actual. No se crea una activación remota.';}
 }catch(e){error(e.message);}
}
$('refresh-rdp').onclick=async()=>{try{await loadRdp();}catch(e){error(e.message);}};


let dashboardRequest=0;
function dailyChart(rows){
 if(!rows.some(r=>r.success||r.failure))return '<div class="empty">No se recibieron accesos para estos filtros. Revisa la cobertura o cambia el periodo.</div>';
 const width=640,height=220,left=40,right=16,top=12,bottom=34,max=Math.max(1,...rows.map(r=>Math.max(r.success,r.failure)));
 const x=i=>left+i*(width-left-right)/Math.max(1,rows.length-1),y=n=>height-bottom-n*(height-top-bottom)/max;
 const points=field=>rows.map((r,i)=>`${x(i).toFixed(1)},${y(r[field]).toFixed(1)}`).join(' ');
 const ticks=[0,Math.ceil(max/2),max];
 const grids=ticks.map(v=>`<line class="chart-grid" x1="${left}" y1="${y(v)}" x2="${width-right}" y2="${y(v)}"/><text class="chart-label" x="${left-8}" y="${y(v)+4}" text-anchor="end">${v}</text>`).join('');
 const indices=[0,Math.floor((rows.length-1)/2),rows.length-1];
 const dates=indices.map(i=>`<text class="chart-label" x="${x(i)}" y="${height-8}" text-anchor="${i===0?'start':i===rows.length-1?'end':'middle'}">${esc(rows[i].day.slice(5))}</text>`).join('');
 const dots=rows.map((r,i)=>`<circle class="chart-dot" cx="${x(i)}" cy="${y(r.success)}" r="3"><title>${esc(r.day)}: ${r.success} correctos; ${r.failure} fallidos</title></circle>`).join('');
 return `<svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Evolución diaria de accesos correctos y fallidos"><title>Accesos diarios; los valores también están en los indicadores y la tabla de usuarios.</title>${grids}<polyline class="chart-success" points="${points('success')}"/><polyline class="chart-failure" points="${points('failure')}"/>${dots}${dates}</svg>`;
}
const eventNames={rdp_success:'Acceso RDP',rdp_failure:'Fallo RDP',rdp_logoff:'Cierre RDP',rdp_reconnect:'Reconexión RDP',rdp_disconnect:'Desconexión RDP',interactive_success:'Acceso / desbloqueo local',interactive_failure:'Fallo interactivo',interactive_logoff:'Cierre interactivo'};
async function loadDashboard(){
 const sequence=++dashboardRequest;busy($('refresh-dashboard'),true);
 $('metrics-provenance').textContent='Actualizando métricas…';
 const selected=$('metrics-server').value;
 const query=new URLSearchParams({days:$('metrics-days').value,server:selected,scope:$('metrics-scope').value,offset:String(-new Date().getTimezoneOffset())});
 try{
 const data=await api('dashboard?'+query);
 if(sequence!==dashboardRequest||state.view!=='dashboard')return;
 $('metrics-basis').textContent=data.demo?'Ejemplos ficticios de demostración':'Confirmados por Windows';
 for(const field of ['success','failure','users','servers'])$('metric-'+field).textContent=data.totals[field].toLocaleString('es-MX');
 $('metrics-server').innerHTML='<option value="">Todos los servidores</option>'+data.available_servers.map(s=>`<option value="${esc(s)}">${esc(s)}</option>`).join('');$('metrics-server').value=selected;
 const active=data.collectors.filter(c=>c.enabled);const healthy=active.filter(c=>c.health==='reportando');
 $('metrics-provenance').textContent=(data.demo?'DEMOSTRACIÓN: métricas ficticias, sin eventos reales de AD. ':'Eventos recibidos de Windows. ')+`Fuentes con señal reciente: ${healthy.length}/${active.length}. Actualizado: ${new Date(data.generated_at*1000).toLocaleTimeString('es-MX')}.`;
 $('daily-chart').innerHTML=dailyChart(data.daily);
 const max=Math.max(1,...data.servers.map(s=>s.success));
 $('server-ranking').innerHTML=data.servers.map(s=>`<div class="rank-item"><div><strong>${esc(s.name)}</strong><span>${s.success.toLocaleString('es-MX')}</span></div><progress class="rank-progress" max="${max}" value="${s.success}" aria-label="${esc(s.name)}: ${s.success} accesos"></progress></div>`).join('')||'<div class="empty">Sin accesos correctos en este periodo.</div>';
 $('network-failure-note').textContent=`${data.totals.network_failures} fallos de red (tipo 3), mostrados aparte: pueden incluir NLA u otros servicios y no se atribuyen automáticamente a RDP. Los recuentos de acceso no representan horas de trabajo ni sesiones activas.`;
 $('metrics-users-body').innerHTML=data.users.map(u=>`<tr><td>${esc(u.name)}</td><td>${u.success}</td><td>${u.failure}</td></tr>`).join('')||'<tr><td colspan="3" class="empty">No hay usuarios con accesos en este periodo.</td></tr>';
 $('metrics-events-caption').textContent=`Últimos ${data.events.length} de ${data.event_count} eventos del periodo. Las reconexiones no se cuentan como nuevos accesos.`;
 $('metrics-events-body').innerHTML=data.events.map(e=>`<tr><td>${esc(new Date(e.occurred*1000).toLocaleString('es-MX'))}</td><td>${esc(e.username)}</td><td>${esc(e.server)}</td><td>${esc(e.ip||'No disponible')}</td><td><span class="badge">${esc(eventNames[e.kind]||e.kind)} · ${e.event_id}</span></td></tr>`).join('')||'<tr><td colspan="5" class="empty">Aún no se reciben eventos para estos filtros.</td></tr>';
 $('collectors-body').innerHTML=data.collectors.map(c=>`<tr><td>${esc(c.server)}${c.demo?' · Ejemplo':''}</td><td>${c.last_seen?esc(new Date(c.last_seen*1000).toLocaleString('es-MX')):'Sin recepción'}</td><td><span class="badge ${c.health==='reportando'?'active':''}">${esc(c.health)}</span></td><td>${c.last_gap?'Brecha detectada: '+esc(new Date(c.last_gap*1000).toLocaleString('es-MX')):'Sin brechas notificadas'}</td><td>${c.enabled&&!c.demo&&!state.desktop?`<button class="secondary" data-revoke-collector="${esc(c.id)}">Revocar</button>`:'—'}</td></tr>`).join('')||'<tr><td colspan="5" class="empty">Registra cada servidor e instala el recolector Windows para recibir métricas reales.</td></tr>';
 $('page-error').hidden=true;
 }catch(e){if(sequence===dashboardRequest){$('metrics-provenance').textContent='No fue posible actualizar; los datos visibles pueden estar desactualizados.';error(e.message);}}
 finally{if(sequence===dashboardRequest)busy($('refresh-dashboard'),false);}
}
$('refresh-dashboard').onclick=loadDashboard;
for(const id of ['metrics-days','metrics-server','metrics-scope'])$(id).onchange=loadDashboard;
$('new-collector').onclick=()=>modal('Registrar servidor Windows','<p>Genera una credencial exclusiva para el recolector de este servidor. Se mostrará una sola vez.</p><label for="collector-name">Nombre del recolector</label><input id="collector-name" name="name" maxlength="100" required><label for="collector-server">Nombre DNS del servidor</label><input id="collector-server" name="server" maxlength="253" placeholder="srv-rdp.empresa.local" required><label for="collector-password">Contraseña de administrador</label><input id="collector-password" name="admin_password" type="password" autocomplete="current-password" required>','Registrar',async data=>{const result=await api('collectors',data);await loadDashboard();showSecret(result.token,'Token del recolector · '+result.server);});
setInterval(()=>{if(state.view==='dashboard'&&!$('workspace').hidden&&!document.hidden&&!$('modal').open)loadDashboard();},60000);

async function boot(){hydrateIcons();document.documentElement.dataset.mode=localStorage.getItem('fk-mode')||'light';try{const info=await api('session');state.csrf=info.csrf;state.desktop=Boolean(info.desktop);if(state.desktop)desktopLabels();if(info.mode==='ad'){$('demo-notice').hidden=true;$('mode-badge').textContent='Active Directory';$('connection-label').textContent='Active Directory';$('connection-detail').textContent='Ámbito de la OU configurada';}if(!info.setup)$('setup-note').textContent='Antes del primer acceso, configura el administrador con python app.py --init-admin en el servidor.';else $('setup-note').textContent=info.desktop?'Aplicación de este servidor · Cuenta Windows actual':info.mode==='demo'?'Entorno de demostración · Sin conexión al dominio':'';if(info.authenticated)await openWorkspace();}catch(e){$('login-error').textContent=e.message;}}
boot();

function desktopLabels(){
 $('new-collector').hidden=true;
 $('setup-note').textContent='Aplicación de este servidor · Cuenta Windows actual';
 pages.dashboard[1]='Métricas del registro Security de este servidor.';
 pages.rdp[1]='Conexiones firmadas y protegidas para usar desde este servidor.';
 const section=$('rdp-view');
 section.querySelector('.card.padded>p').textContent='Prepara conexiones para este servidor y la cuenta Windows actual. La credencial queda cifrada con DPAPI.';
 section.querySelector('.rdp-steps').innerHTML='<article><span class="step-number">1</span><div><strong>Define la conexión</strong><p>Servidor de destino y cuenta con permiso RDP.</p></div></article><article><span class="step-number">2</span><div><strong>Firma y protege</strong><p>Los certificados firman el perfil y el lanzador. Windows protege la contraseña.</p></div></article><article><span class="step-number">3</span><div><strong>Conecta desde este servidor</strong><p>Extrae el ZIP y ejecuta Conectar.ps1 con la misma cuenta Windows.</p></div></article>';
 section.querySelector('.rdp-history h2').textContent='Clientes locales preparados';
 section.querySelector('.rdp-history p').textContent='Elimina la credencial en el Administrador de credenciales de Windows para retirar su almacenamiento local.';
 section.querySelector('th:nth-child(3)').textContent='Fecha de preparación';
}
