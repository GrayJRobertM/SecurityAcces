'use strict';
const mapState={data:null,selected:null,cursor:null,request:0,detailRequest:0,world:null,nodes:[],camera:{x:0,y:0,z:1},drag:null};
const mapEventNames={...eventNames,network_failure:'Intento de red fallido',other_failure:'Intento fallido',other_success:'Acceso registrado',other_logoff:'Cierre de sesión'};
function mapQuery(){return new URLSearchParams({days:$('map-days').value,outcome:$('map-outcome').value,user:$('map-user').value,offset:String(-new Date().getTimezoneOffset())});}
function markerClass(point){return point.success&&point.failure?'mixed':point.failure?'failure':point.success?'success':'session';}
function applyMapCamera(){
 const cam=mapState.camera;cam.x=Math.min(0,Math.max(1000*(1-cam.z),cam.x));cam.y=Math.min(0,Math.max(500*(1-cam.z),cam.y));
 $('access-countries').setAttribute('transform',`translate(${cam.x} ${cam.y}) scale(${cam.z})`);
 for(const {button,point} of mapState.nodes){const x=(point.longitude+180)/360*1000*cam.z+cam.x,y=(90-point.latitude)/180*500*cam.z+cam.y;button.style.left=x/10+'%';button.style.top=y/5+'%';button.hidden=x<0||x>1000||y<0||y>500;button.classList.toggle('selected',point.id===mapState.selected);}
 $('map-zoom-out').disabled=cam.z<=1;$('map-zoom-in').disabled=cam.z>=8;
}
function zoomMap(factor,x=500,y=250){const cam=mapState.camera,z=Math.min(8,Math.max(1,cam.z*factor));cam.x=x-(x-cam.x)*z/cam.z;cam.y=y-(y-cam.y)*z/cam.z;cam.z=z;applyMapCamera();}
function resetMapDetails(){mapState.selected=null;mapState.cursor=null;mapState.detailRequest++;$('map-detail-title').textContent='Selecciona un punto';$('map-detail-note').textContent='Verás todas las cuentas registradas en este origen.';$('map-detail-list').replaceChildren();$('map-more').hidden=true;}
async function loadAccessMap(preserve=false){
 const sequence=++mapState.request;const selected=preserve?mapState.selected:null;busy($('refresh-map'),true);$('map-provenance').textContent='Consultando eventos y ubicaciones locales…';resetMapDetails();
 try{
  if(!mapState.world){const response=await fetch('/static/maps/world.svg');if(!response.ok)throw new Error('No se pudo cargar la cartografía local.');const svg=new DOMParser().parseFromString(await response.text(),'image/svg+xml');for(const path of svg.querySelectorAll('path')){const d=path.getAttribute('d');if(!/^[MLZ0-9.,\s-]+$/.test(d))throw new Error('Cartografía inválida.');const node=document.createElementNS('http://www.w3.org/2000/svg','path');node.setAttribute('d',d);$('access-countries').append(node);}mapState.world=true;}
  const data=await api('map?'+mapQuery());if(sequence!==mapState.request||state.view!=='map')return;
  mapState.data=data;$('map-markers').replaceChildren();mapState.nodes=[];
  for(const point of data.points){const button=document.createElement('button');button.type='button';button.className='map-point '+markerClass(point);button.setAttribute('aria-label',`${point.label}: ${point.events} eventos, ${point.success} accesos, ${point.failure} intentos fallidos. Ver usuarios.`);const count=document.createElement('span');count.textContent=point.events>99?'99+':point.events;button.append(count);button.onclick=()=>openMapDetails(point.id);$('map-markers').append(button);mapState.nodes.push({button,point});}
  applyMapCamera();$('map-empty').hidden=data.points.length>0;
  $('map-summary').textContent=`${data.points.length} ubicaciones · ${data.located_events} de ${data.totals.events} eventos ubicados · ${data.totals.users} cuentas en el periodo`;
  $('map-provenance').textContent=(data.demo?'DEMOSTRACIÓN: eventos y ubicaciones ficticios. ':'Ubicación aproximada calculada en este servidor. ')+(data.database.available?`${data.database.source}${data.database.date?' · Base: '+data.database.date:''}.`:'Base local no disponible; los eventos siguen visibles sin ubicación.')+(data.truncated?` Se muestran los ${data.origin_limit} orígenes más recientes; filtra por usuario o reduce el periodo para consultar otros.`:'');
  $('map-locations-body').innerHTML=data.points.map(p=>`<tr><td>${esc(p.label)}</td><td>${p.origins}</td><td>${p.success}</td><td>${p.failure}</td><td><button class="secondary" data-map-point="${esc(p.id)}">Ver usuarios</button></td></tr>`).join('')||'<tr><td colspan="5" class="empty">Sin ubicaciones para este periodo.</td></tr>';
  $('map-unlocated-body').innerHTML=data.unlocated.map(p=>`<tr><td>${esc(p.ip||'Sin IP')}</td><td>${esc(p.reason)}</td><td>${p.events}</td><td>${p.users}</td><td><button class="secondary" data-map-point="${esc(p.id)}">Ver usuarios</button></td></tr>`).join('')||'<tr><td colspan="5" class="empty">No hay orígenes sin ubicación para estos filtros.</td></tr>';
  if(selected&&(data.points.some(p=>p.id===selected)||data.unlocated.some(p=>p.id===selected)))await openMapDetails(selected);
 }catch(error){if(sequence===mapState.request){$('map-provenance').textContent='No se pudo actualizar el mapa. Los datos visibles pueden estar desactualizados.';window.error(error.message);}}
 finally{if(sequence===mapState.request)busy($('refresh-map'),false);}
}
async function openMapDetails(identifier,more=false){
 const sequence=++mapState.detailRequest;const point=mapState.data?.points.find(p=>p.id===identifier)||mapState.data?.unlocated.find(p=>p.id===identifier);if(!point)return;
 mapState.selected=identifier;applyMapCamera();$('map-detail-title').textContent=point.label||point.ip||'Origen sin IP';$('map-detail-note').textContent=point.label?'Ubicación aproximada · Cuentas y eventos de todas las IPs de este punto.':point.reason;
 if(!more){$('map-detail-list').innerHTML='<p class="helper">Consultando eventos…</p>';mapState.cursor=null;}
 $('map-more').hidden=true;const query=mapQuery();query.set('point',identifier);if(more&&mapState.cursor)query.set('before',mapState.cursor);
 try{const data=await api('map/events?'+query);if(sequence!==mapState.detailRequest)return;const html=data.events.map(event=>`<article class="map-event"><strong>${esc(event.username)}</strong><span class="badge ${event.event_id===4625?'failure':'active'}">${esc(mapEventNames[event.kind]||'Evento Windows')}</span><p>${esc(new Date(event.occurred*1000).toLocaleString('es-MX'))}</p><p>IP: ${esc(event.ip||'Sin IP')}<br>Servidor: ${esc(event.server)}<br>Evento ${event.event_id} · Tipo ${event.logon_type}</p>${event.event_id===4625?'<p>Cuenta declarada en el intento; autenticación no confirmada.</p>':''}</article>`).join('')||'<p class="helper">No hay eventos para estos filtros.</p>';if(more)$('map-detail-list').insertAdjacentHTML('beforeend',html);else $('map-detail-list').innerHTML=html;mapState.cursor=data.next_cursor;$('map-more').hidden=!data.next_cursor;}
 catch(error){if(sequence===mapState.detailRequest){if(!more)$('map-detail-list').textContent=error.message;else toast(error.message);}}
}
$('refresh-map').onclick=()=>loadAccessMap(true);$('map-days').onchange=()=>loadAccessMap();$('map-outcome').onchange=()=>loadAccessMap();
let mapSearchTimer;$('map-user').oninput=()=>{clearTimeout(mapSearchTimer);mapSearchTimer=setTimeout(()=>loadAccessMap(),350);};
$('map-more').onclick=()=>openMapDetails(mapState.selected,true);
$('map-zoom-in').onclick=()=>zoomMap(1.5);$('map-zoom-out').onclick=()=>zoomMap(1/1.5);$('map-reset').onclick=()=>{mapState.camera={x:0,y:0,z:1};applyMapCamera();};
document.addEventListener('click',event=>{const button=event.target.closest('[data-map-point]');if(button)openMapDetails(button.dataset.mapPoint);});
const mapCanvas=$('map-canvas');
mapCanvas.addEventListener('wheel',event=>{event.preventDefault();const box=mapCanvas.getBoundingClientRect();zoomMap(event.deltaY<0?1.2:1/1.2,(event.clientX-box.left)/box.width*1000,(event.clientY-box.top)/box.height*500);},{passive:false});
mapCanvas.onpointerdown=event=>{if(event.target.closest('button'))return;mapState.drag={x:event.clientX,y:event.clientY,camX:mapState.camera.x,camY:mapState.camera.y};mapCanvas.setPointerCapture(event.pointerId);mapCanvas.classList.add('dragging');};
mapCanvas.onpointermove=event=>{if(!mapState.drag)return;const box=mapCanvas.getBoundingClientRect();mapState.camera.x=mapState.drag.camX+(event.clientX-mapState.drag.x)/box.width*1000;mapState.camera.y=mapState.drag.camY+(event.clientY-mapState.drag.y)/box.height*500;applyMapCamera();};
mapCanvas.onpointerup=mapCanvas.onpointercancel=()=>{mapState.drag=null;mapCanvas.classList.remove('dragging');};
setInterval(()=>{if(state.view==='map'&&!$('workspace').hidden&&!document.hidden&&!$('modal').open)loadAccessMap(true);},60000);
