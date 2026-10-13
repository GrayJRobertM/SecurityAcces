'use strict';
const byId=id=>document.getElementById(id);
let csrf='';
function modeFields(){const enabled=byId('mode').value==='ad';byId('ad-fields').hidden=!enabled;byId('local-help').hidden=byId('mode').value!=='local';byId('ad-fields').querySelectorAll('input').forEach(input=>input.disabled=!enabled);}
byId('mode').onchange=modeFields;
byId('setup-form').onsubmit=async event=>{
 event.preventDefault();const button=byId('save');button.disabled=true;button.setAttribute('aria-busy','true');byId('setup-error').textContent='';
 try{const response=await fetch('/desktop/settings',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify(Object.fromEntries(new FormData(event.target)))});const data=await response.json();if(!response.ok)throw new Error(data.error);event.target.reset();location.replace('/');}
 catch(error){byId('setup-error').textContent=error.message||'No se pudo guardar la configuración.';}
 finally{button.disabled=false;button.setAttribute('aria-busy','false');}
};
(async()=>{try{const response=await fetch('/desktop/settings');if(!response.ok)throw new Error('No se pudo cargar la configuración.');const data=await response.json();csrf=data.csrf;for(const [name,value] of Object.entries(data.settings)){const element=byId(name);if(element)element.value=value;}if(data.configured){byId('confirmation-field').hidden=true;byId('confirmation').disabled=true;byId('password').autocomplete='current-password';byId('password-help').textContent='Confirma la contraseña administrativa del entorno actual. Cambiar de entorno conserva los datos anteriores separados y abre los del destino.';}modeFields();}catch(error){byId('setup-error').textContent=error.message;byId('save').disabled=true;}})();
