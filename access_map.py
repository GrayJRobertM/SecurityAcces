"""Offline IP locations and authenticated access-map aggregation; no external lookups."""
import hashlib
import ipaddress
import math
import sqlite3
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from flask import jsonify, request
from telemetry import hostname

BASE = Path(__file__).parent
ORIGIN_LIMIT = 2000
EVENT_LIMIT = 100
DEMO_CITIES = [
    (19.4326,-99.1332,'Ciudad de México, México'),
    (20.6597,-103.3496,'Guadalajara, México'),
    (4.7110,-74.0721,'Bogotá, Colombia'),
    (40.4168,-3.7038,'Madrid, España'),
    (32.7767,-96.7970,'Dallas, Estados Unidos')]


class Locator:
    def __init__(self, database=None, demo=False):
        self.reader = None
        self.demo = demo
        self.info = dict(available=False, source='DB-IP City Lite', date=None, offline=True)
        if demo:
            self.info.update(available=True, source='Ubicaciones ficticias de demostración')
        elif database and Path(database).is_file():
            import maxminddb
            try:
                self.reader = maxminddb.open_database(str(database))
                stamp = self.reader.metadata().build_epoch
                self.info.update(available=True, date=datetime.fromtimestamp(stamp,timezone.utc).strftime('%Y-%m-%d'))
            except (OSError,ValueError,maxminddb.InvalidDatabaseError):
                if self.reader:
                    self.reader.close()
                    self.reader=None
                self.info['error']='No se pudo abrir la base local de geolocalización.'

    def close(self):
        if self.reader:
            self.reader.close()

    def lookup(self, raw):
        missing = dict(located=False, reason='Sin IP de origen')
        try:
            address = ipaddress.ip_address(raw)
            if isinstance(address,ipaddress.IPv6Address) and address.ipv4_mapped:
                address=address.ipv4_mapped
        except ValueError:
            return dict(missing,reason='IP ausente o inválida')
        if self.demo and str(address).startswith('192.0.2.'):
            if str(address)=='192.0.2.25':
                return dict(missing,reason='Ejemplo sin ubicación')
            lat,lon,label=DEMO_CITIES[int(str(address).split('.')[-1]) % len(DEMO_CITIES)]
            return dict(located=True,latitude=lat,longitude=lon,label=label,approximate=True,demo=True)
        if not address.is_global or address.is_multicast or address.is_reserved or address.is_unspecified:
            return dict(missing,reason='IP privada, local o no geolocalizable')
        if not self.reader:
            return dict(missing,reason='Base local de geolocalización no disponible')
        record = self.reader.get(str(address)) or {}
        location = record.get('location',{})
        lat,lon=location.get('latitude'),location.get('longitude')
        if not all(type(value) in (float,int) and math.isfinite(value) for value in (lat,lon)):
            return dict(missing,reason='IP pública sin coordenadas en la base local')
        if not -90<=lat<=90 or not -180<=lon<=180 or (lat==0 and lon==0):
            return dict(missing,reason='Coordenadas no disponibles')
        def name(part):
            names=record.get(part,{}).get('names',{})
            return names.get('es') or names.get('en') or ''
        label=', '.join(value for value in (name('city'),name('country')) if value) or 'Ubicación aproximada por IP'
        return dict(located=True,latitude=lat,longitude=lon,label=label,approximate=True)


def filters(args, mode, now=None):
    now=now or time.time()
    try:
        days=int(args.get('days','7')); offset=int(args.get('offset','-360'))
    except (TypeError,ValueError):raise ValueError('Periodo inválido.')
    if days not in (7,30,90) or not -840<=offset<=840:raise ValueError('Periodo inválido.')
    outcome=args.get('outcome','all')
    if outcome not in ('all','success','failure','session'):raise ValueError('Selecciona un tipo de evento válido.')
    source='demo' if mode=='demo' else 'windows'
    first=(datetime.fromtimestamp(now,timezone.utc)+timedelta(minutes=offset)-timedelta(days=days-1)).replace(hour=0,minute=0,second=0,microsecond=0)
    cutoff=(first-timedelta(minutes=offset)).timestamp()
    where='source=? AND occurred>=? AND occurred<=?'
    params=[source,cutoff,now]
    if args.get('server'):
        where+=' AND server=?';params.append(hostname(args['server']))
    user=args.get('user','')
    if not isinstance(user,str) or len(user)>256 or any(ord(c)<32 for c in user):raise ValueError('Filtro de usuario inválido.')
    if user.strip():
        escaped=user.strip().casefold().replace('\\','\\\\').replace('%','\\%').replace('_','\\_')
        where+=" AND identity LIKE ? ESCAPE '\\'";params.append('%'+escaped+'%')
    if outcome=='success':where+=" AND kind IN ('rdp_success','interactive_success','rdp_reconnect')"
    elif outcome=='failure':where+=" AND event_id=4625"
    elif outcome=='session':where+=" AND event_id IN (4634,4778,4779)"
    return where,params


def model(db,args,mode,locator,now=None):
    where,params=filters(args,mode,now)
    rows=db.execute("SELECT ip,COUNT(*) AS events,SUM(kind IN ('rdp_success','interactive_success')) AS success,SUM(event_id=4625) AS failure,COUNT(DISTINCT identity) AS users,MAX(occurred) AS last_seen FROM windows_events WHERE "+where+' GROUP BY ip ORDER BY last_seen DESC,ip LIMIT ?',params+[ORIGIN_LIMIT+1]).fetchall()
    truncated=len(rows)>ORIGIN_LIMIT
    rows=rows[:ORIGIN_LIMIT]
    points={};unlocated=[];selection={}
    for row in rows:
        origin=dict(row)
        geo=locator.lookup(origin['ip'])
        if geo['located']:
            identifier=f"{geo['latitude']:.3f},{geo['longitude']:.3f}"
            if identifier not in points:
                points[identifier]=dict(id=identifier,latitude=geo['latitude'],longitude=geo['longitude'],label=geo['label'],
                                        events=0,success=0,failure=0,origins=0,approximate=True)
                selection[identifier]=[]
            point=points[identifier]
            for field in ('events','success','failure'):point[field]+=origin[field]
            point['origins']+=1
            selection[identifier].append(origin['ip'])
        else:
            identifier='unknown-'+hashlib.sha256(origin['ip'].encode()).hexdigest()[:24]
            unlocated.append(dict(origin,id=identifier,reason=geo['reason']))
            selection[identifier]=[origin['ip']]
    totals=dict(db.execute('SELECT COUNT(*) AS events,COUNT(DISTINCT identity) AS users,COUNT(DISTINCT ip) AS origins FROM windows_events WHERE '+where,params).fetchone())
    return dict(demo=mode=='demo',points=list(points.values()),unlocated=unlocated,totals=totals,
                located_events=sum(p['events'] for p in points.values()),database=locator.info,
                truncated=truncated,origin_limit=ORIGIN_LIMIT,generated_at=now or time.time()),selection


def register(app,db):
    def locator():
        override=Path(app.config['DATA_DIR']).parent/'geodata'/'city.mmdb'
        bundled=BASE/'geodata'/'city.mmdb'
        return Locator(override if override.is_file() else bundled,demo=app.config['MODE']=='demo')

    @app.get('/api/map')
    def access_map():
        geo=locator()
        try:
            data,_=model(db(),request.args,app.config['MODE'],geo)
            return jsonify(data)
        finally:geo.close()

    @app.get('/api/map/events')
    def point_events():
        geo=locator()
        try:
            data,selection=model(db(),request.args,app.config['MODE'],geo)
            identifier=request.args.get('point','')
            if identifier not in selection:return jsonify(error='El punto ya no está en este periodo. Actualiza el mapa.'),404
            try:cursor=int(request.args.get('before','0'))
            except ValueError:raise ValueError('Cursor inválido.')
            if not 0<=cursor<=2**63-1:raise ValueError('Cursor inválido.')
            where,params=filters(request.args,app.config['MODE'])
            ips=selection[identifier]
            where+=' AND ip IN ('+','.join('?' for _ in ips)+')';params+=ips
            if cursor:where+=' AND id<?';params.append(cursor)
            events=[dict(row) for row in db().execute('SELECT id,server,occurred,username,ip,event_id,logon_type,kind FROM windows_events WHERE '+where+' ORDER BY id DESC LIMIT ?',params+[EVENT_LIMIT+1])]
            more=len(events)>EVENT_LIMIT
            events=events[:EVENT_LIMIT]
            return jsonify(events=events,next_cursor=events[-1]['id'] if more else None,demo=data['demo'])
        finally:geo.close()
