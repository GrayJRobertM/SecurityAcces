'use strict';
let updateState=null,updatePoll=null;
function scheduleUpdatePoll(){
 clearTimeout(updatePoll);
 if($('workspace').hidden)return;
 updatePoll=setTimeout(async()=>{try{await loadUpdates();}catch(e){if(state.view==='updates')error(e.message);scheduleUpdatePoll();}},updateState&&['checking','downloading','preparing','installing'].includes(updateState.phase)?1500:60000);
}
async function loadUpdates(){
 const data=await api('updates/status');updateState=data;
 $('update-installed').textContent=data.installed;
 $('update-latest').textContent=data.latest?data.latest.version:(data.phase==='current'?'Al día':'Sin versión nueva');
 $('update-checked').textContent=data.checked_at?new Date(data.checked_at*1000).toLocaleString('es-MX'):'Sin consultar';
 $('update-status').textContent=data.message;
 const running=['checking','downloading','preparing','installing'].includes(data.phase),owner=data.owner;
 $('update-check').disabled=!owner||running||data.phase==='ready';
 $('update-check').setAttribute('aria-busy',String(data.phase==='checking'));
 $('update-download').hidden=!data.latest||data.phase==='ready'||['preparing','installing'].includes(data.phase);
 $('update-download').disabled=!owner||!data.can_install||running;
 $('update-download').setAttribute('aria-busy',String(data.phase==='downloading'));
 $('update-apply').hidden=data.phase!=='ready';$('update-apply').disabled=!owner||!data.can_install;
 $('update-owner-note').textContent=!owner?'Para instalar, inicia sesión como admin en Metakampo Access desde la cuenta Windows propietaria original.':!data.can_install?'Esta vista permite consultar versiones. Para instalar, abre la aplicación instalada en Windows.':'Solo se instalarán paquetes firmados del repositorio oficial. Confirma cuando puedas interrumpir temporalmente Metakampo.';
 const transfer=data.phase==='downloading';for(const id of ['update-progress','update-progress-label','update-transfer'])$(id).hidden=!transfer;
 if(transfer&&data.latest){$('update-progress').value=Math.min(100,100*data.received/data.latest.size);$('update-transfer').textContent=`${(data.received/1048576).toFixed(1)} de ${(data.latest.size/1048576).toFixed(1)} MB`;}
 $('update-notice').hidden=!data.latest||['preparing','installing'].includes(data.phase);
 $('update-last-result').hidden=!data.last_result;
 if(data.last_result)$('update-last-result').textContent=`Última instalación: ${data.last_result.message||'Consulta el resultado en el servidor.'}`;
 scheduleUpdatePoll();
}
async function updateAction(action,body={}){
 const button=$('update-'+action);busy(button,true);
 try{await api('updates/'+action,body);await loadUpdates();}catch(e){busy(button,false);error(e.message);}
}
$('update-check').onclick=()=>updateAction('check');
$('update-download').onclick=()=>updateAction('download');
$('update-apply').onclick=()=>{
 if(!updateState?.latest)return;const target=updateState.latest.version;
 modal('Actualizar a Metakampo '+target,`<p>Se creará una copia de seguridad de los datos cifrados antes de cerrar Metakampo.</p><div class="notice">Se cerrarán las ventanas de Metakampo de este servidor y se pausarán temporalmente la recolección, los avisos y el acceso compartido. Las sesiones RDP de Windows permanecen abiertas. Espera a que termine cualquier importación.</div><p>La aplicación se volverá a abrir con la misma cuenta Windows. El equipo no se reiniciará automáticamente.</p><label for="update-password">Contraseña del propietario de Metakampo</label><input id="update-password" name="admin_password" type="password" autocomplete="current-password" required>`,'Confirmar actualización',async data=>{
  await api('updates/apply',{version:target,admin_password:data.admin_password});closeModal();await loadUpdates();
 });
};
// Check the local state after login; only the installed owner performs network checks.
document.addEventListener('click',e=>{if(e.target.closest('[data-view="updates"]'))clearTimeout(updatePoll);});
setTimeout(async()=>{if(!$('workspace').hidden){try{await loadUpdates();}catch{scheduleUpdatePoll();}}},2000);
