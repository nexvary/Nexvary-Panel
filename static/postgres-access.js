(()=>{
  const root=document.getElementById('postgresAccessManager');
  if(!root)return;
  const csrf=document.querySelector('meta[name="csrf-token"]')?.content||'';
  const stepUp=root.dataset.stepUp==='1';
  const role=root.dataset.role||'viewer';
  const $=s=>root.querySelector(s);
  const esc=v=>String(v??'').replace(/[&<>'"]/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[ch]));
  const state={roles:[],databases:[],grants:[],profiles:[]};

  function status(message,type=''){
    const node=$('#postgresAccessStatus');if(!node)return;
    node.textContent=message;node.className=`database-access-status ${type}`.trim();
  }
  async function api(url,options={}){
    const opts={credentials:'same-origin',...options,headers:{Accept:'application/json',...(options.headers||{})}};
    if(opts.method&&opts.method!=='GET')opts.headers['X-CSRF-Token']=csrf;
    const res=await fetch(url,opts);let data={};
    try{data=await res.json();}catch{data={ok:false,error:`HTTP ${res.status}`};}
    if(!res.ok||data.ok===false){const err=new Error(data.error||`HTTP ${res.status}`);err.status=res.status;throw err;}
    return data;
  }
  const jsonBody=payload=>({headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});

  function appRoles(){return state.roles.filter(x=>!x.managed_owner_role);}
  function renderSelects(){
    const db=$('#postgresGrantDb');
    if(db)db.innerHTML='<option value="">اختر قاعدة…</option>'+state.databases.map(x=>`<option value="${esc(x.db_name)}">${esc(x.db_name)} · ${esc(x.owner)}</option>`).join('');
    const roleOptions='<option value="">اختر Role…</option>'+appRoles().map(x=>`<option value="${esc(x.username)}">${esc(x.username)} · ${esc(x.owner)}</option>`).join('');
    if($('#postgresGrantRole'))$('#postgresGrantRole').innerHTML=roleOptions;
    const rotate='<option value="">اختر Role…</option>'+state.roles.map(x=>`<option value="${esc(x.username)}">${esc(x.username)}${x.managed_owner_role?' · OWNER':''}</option>`).join('');
    if($('#postgresPasswordRole'))$('#postgresPasswordRole').innerHTML=rotate;
    const profiles=$('#postgresGrantProfile');
    if(profiles)profiles.innerHTML=state.profiles.map(x=>`<option value="${esc(x)}">${esc(x)}</option>`).join('');
  }
  function renderRoles(){
    const target=$('#postgresAccessRoles');if(!target)return;
    if(!state.roles.length){target.innerHTML='<div class="empty-state">لا توجد PostgreSQL Roles مسجلة.</div>';return;}
    target.innerHTML=state.roles.map(item=>{
      const grants=state.grants.filter(g=>g.db_user===item.username).length;
      const locked=item.managed_owner_role||grants>0||!stepUp||role==='viewer';
      return `<article class="database-access-row"><div><b>${esc(item.username)}</b><small>${esc(item.owner)} · ${item.managed_owner_role?'DATABASE OWNER':'APP ROLE'} · ${grants} profile(s)</small></div><button type="button" class="ghost" data-pg-role-delete="${esc(item.username)}" ${locked?'disabled':''}>حذف</button></article>`;
    }).join('');
  }
  function renderGrants(){
    const target=$('#postgresAccessGrants');if(!target)return;
    if(!state.grants.length){target.innerHTML='<div class="empty-state">لا توجد PostgreSQL Grant Profiles.</div>';return;}
    target.innerHTML=state.grants.map(item=>`<article class="database-access-row database-grant-row"><div><b>${esc(item.db_user)} → ${esc(item.db_name)}</b><small>PROFILE · ${esc(item.profile)}</small></div><button type="button" class="ghost" data-pg-grant-db="${esc(item.db_name)}" data-pg-grant-role="${esc(item.db_user)}">تحرير</button></article>`).join('');
  }
  function render(data){
    state.roles=data.roles||[];state.databases=data.databases||[];state.grants=data.grants||[];state.profiles=data.profiles||[];
    $('#postgresRoleCount').textContent=String(state.roles.length);
    $('#postgresGrantCount').textContent=String(state.grants.length);
    const q=data.quota||{};$('#postgresRoleQuota').textContent=`${Number(q.used||0)}/${Number(q.limit||0)}`;
    const badge=$('#postgresProviderState');const provider=data.provider||{};
    if(badge)badge.textContent=provider.online?'ONLINE':'OFFLINE';
    root.classList.toggle('provider-offline',!provider.online);
    renderSelects();renderRoles();renderGrants();
  }
  async function load(){
    try{render(await api('/api/database-access/postgresql'));}
    catch(err){status(`تعذر تحميل PostgreSQL Access Manager: ${err.message}`,'error');}
  }

  $('#postgresRoleCreateForm')?.addEventListener('submit',async event=>{
    event.preventDefault();if(!stepUp){status('Step-Up مطلوب قبل إنشاء PostgreSQL Role.','error');return;}
    const fd=new FormData(event.currentTarget);const payload={username:String(fd.get('username')||''),password:String(fd.get('password')||'')};
    const owner=String(fd.get('owner')||'').trim();if(owner)payload.owner=owner;
    try{await api('/api/database-access/postgresql/roles',{method:'POST',...jsonBody(payload)});event.currentTarget.reset();status('تم إنشاء PostgreSQL Role بصلاحيات غير مميزة وبدون حفظ كلمة المرور.','ok');await load();}
    catch(err){status(err.status===428?'انتهت نافذة Step-Up؛ أعد التحقق.':err.message,'error');}
  });

  async function applyProfile(profile){
    const db=$('#postgresGrantDb')?.value||'';const username=$('#postgresGrantRole')?.value||'';
    if(!db||!username){status('اختر قاعدة وRole أولًا.','error');return;}
    if(!stepUp){status('Step-Up مطلوب لتعديل PostgreSQL Grants.','error');return;}
    try{await api('/api/database-access/postgresql/grants',{method:'PUT',...jsonBody({db_name:db,username,profile})});status(profile==='none'?'تم سحب Grant Profile بالكامل.':`تم تطبيق Profile: ${profile}.`,'ok');await load();}
    catch(err){status(err.status===428?'انتهت نافذة Step-Up.':err.message,'error');}
  }
  $('#postgresGrantForm')?.addEventListener('submit',event=>{event.preventDefault();applyProfile($('#postgresGrantProfile')?.value||'');});
  $('#postgresGrantRevoke')?.addEventListener('click',()=>applyProfile('none'));

  $('#postgresPasswordForm')?.addEventListener('submit',async event=>{
    event.preventDefault();if(!stepUp){status('Step-Up مطلوب لتدوير كلمة المرور.','error');return;}
    const fd=new FormData(event.currentTarget);const username=String(fd.get('username')||'');const password=String(fd.get('password')||'');if(!username)return;
    try{await api(`/api/database-access/postgresql/roles/${encodeURIComponent(username)}/password`,{method:'PUT',...jsonBody({password})});event.currentTarget.reset();status('تم تدوير كلمة المرور؛ لم تُحفظ في SQLite أو Audit.','ok');await load();}
    catch(err){status(err.status===428?'انتهت نافذة Step-Up.':err.message,'error');}
  });

  $('#postgresAccessRoles')?.addEventListener('click',async event=>{
    const btn=event.target.closest('[data-pg-role-delete]');if(!btn)return;
    if(!stepUp){status('Step-Up مطلوب لحذف Role.','error');return;}
    try{await api(`/api/database-access/postgresql/roles/${encodeURIComponent(btn.dataset.pgRoleDelete)}`,{method:'DELETE'});status('تم حذف PostgreSQL Role بعد التحقق من عدم وجود Grants أو ملكية قواعد.','ok');await load();}
    catch(err){status(err.message,'error');}
  });
  $('#postgresAccessGrants')?.addEventListener('click',event=>{
    const btn=event.target.closest('[data-pg-grant-db]');if(!btn)return;
    const db=btn.dataset.pgGrantDb||'';const username=btn.dataset.pgGrantRole||'';const grant=state.grants.find(x=>x.db_name===db&&x.db_user===username);if(!grant)return;
    if($('#postgresGrantDb'))$('#postgresGrantDb').value=db;if($('#postgresGrantRole'))$('#postgresGrantRole').value=username;if($('#postgresGrantProfile'))$('#postgresGrantProfile').value=grant.profile||'';
    $('#postgresGrantForm')?.scrollIntoView({behavior:'smooth',block:'center'});
  });
  load();
})();
