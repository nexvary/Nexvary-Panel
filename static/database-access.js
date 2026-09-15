(()=>{
  const root=document.getElementById('databaseAccessManager');
  if(!root) return;
  const csrf=document.querySelector('meta[name="csrf-token"]')?.content||'';
  const stepUp=root.dataset.stepUp==='1';
  const role=root.dataset.role||'viewer';
  const $=s=>root.querySelector(s);
  const esc=v=>String(v??'').replace(/[&<>'"]/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[ch]));
  const state={users:[],databases:[],grants:[],privileges:[]};

  function status(message,type=''){
    const node=$('#databaseAccessStatus');
    if(!node) return;
    node.textContent=message;
    node.className=`database-access-status ${type}`.trim();
  }
  async function api(url,options={}){
    const opts={credentials:'same-origin',...options,headers:{Accept:'application/json',...(options.headers||{})}};
    if(opts.method&&opts.method!=='GET') opts.headers['X-CSRF-Token']=csrf;
    const res=await fetch(url,opts);let data={};
    try{data=await res.json();}catch{data={ok:false,error:`HTTP ${res.status}`};}
    if(!res.ok||data.ok===false){const err=new Error(data.error||`HTTP ${res.status}`);err.status=res.status;throw err;}
    return data;
  }
  const jsonBody=payload=>({headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});

  function renderSelects(){
    const db=$('#databaseGrantDb');
    const grantUser=$('#databaseGrantUser');
    const passwordUser=$('#databasePasswordUser');
    if(db) db.innerHTML='<option value="">اختر قاعدة…</option>'+state.databases.map(x=>`<option value="${esc(x.db_name)}">${esc(x.db_name)} · ${esc(x.owner)}</option>`).join('');
    const users='<option value="">اختر مستخدمًا…</option>'+state.users.map(x=>`<option value="${esc(x.username)}">${esc(x.username)} · ${esc(x.owner)}</option>`).join('');
    if(grantUser) grantUser.innerHTML=users;
    if(passwordUser) passwordUser.innerHTML=users;
    const privileges=$('#databaseGrantPrivileges');
    if(privileges) privileges.innerHTML=state.privileges.map(x=>`<option value="${esc(x)}">${esc(x)}</option>`).join('');
  }

  function renderUsers(){
    const target=$('#databaseAccessUsers');if(!target)return;
    if(!state.users.length){target.innerHTML='<div class="empty-state">لا توجد Database Users مستقلة.</div>';return;}
    target.innerHTML=state.users.map(user=>{
      const grants=state.grants.filter(g=>g.db_user===user.username).length;
      const disabled=!stepUp||role==='viewer'||grants>0;
      return `<article class="database-access-row"><div><b>${esc(user.username)}</b><small>${esc(user.owner)} · MariaDB · ${grants} grant(s)</small></div><button type="button" class="ghost" data-db-user-delete="${esc(user.username)}" ${disabled?'disabled':''}>حذف</button></article>`;
    }).join('');
  }

  function renderGrants(){
    const target=$('#databaseAccessGrants');if(!target)return;
    if(!state.grants.length){target.innerHTML='<div class="empty-state">لا توجد Grants مسجلة.</div>';return;}
    target.innerHTML=state.grants.map(grant=>`<article class="database-access-row database-grant-row"><div><b>${esc(grant.db_user)} → ${esc(grant.db_name)}</b><small>${(grant.privileges||[]).map(esc).join(' · ')||'NO PRIVILEGES'}</small></div><button type="button" class="ghost" data-db-grant-edit="${esc(grant.db_name)}" data-db-grant-user="${esc(grant.db_user)}">تحرير</button></article>`).join('');
  }

  function render(data){
    state.users=data.users||[];state.databases=data.databases||[];state.grants=data.grants||[];state.privileges=data.privilege_catalog||[];
    $('#databaseUserCount').textContent=String(state.users.length);
    $('#databaseGrantCount').textContent=String(state.grants.length);
    const quota=data.quota||{};$('#databaseUserQuota').textContent=`${Number(quota.used||0)}/${Number(quota.limit||0)}`;
    const provider=data.provider||{};const badge=$('#databaseProviderState');
    if(badge) badge.textContent=provider.online?`ONLINE${provider.version?' · '+provider.version:''}`:'OFFLINE';
    root.classList.toggle('provider-offline',!provider.online);
    renderSelects();renderUsers();renderGrants();
  }

  async function load(){
    try{render(await api('/api/database-access'));}
    catch(err){status(`تعذر تحميل Database Access Manager: ${err.message}`,'error');}
  }

  $('#databaseUserCreateForm')?.addEventListener('submit',async event=>{
    event.preventDefault();
    if(!stepUp){status('Step-Up مطلوب قبل إنشاء Database User.','error');return;}
    const fd=new FormData(event.currentTarget);
    const payload={username:String(fd.get('username')||''),password:String(fd.get('password')||'')};
    const owner=String(fd.get('owner')||'').trim();if(owner)payload.owner=owner;
    try{await api('/api/database-access/users',{method:'POST',...jsonBody(payload)});event.currentTarget.reset();status('تم إنشاء مستخدم MariaDB بدون حفظ كلمة المرور في اللوحة.','ok');await load();}
    catch(err){status(err.status===428?'انتهت نافذة Step-Up؛ أعد التحقق من Security.':err.message,'error');}
  });

  async function applyGrant(privileges){
    const db=$('#databaseGrantDb')?.value||'';const username=$('#databaseGrantUser')?.value||'';
    if(!db||!username){status('اختر قاعدة ومستخدمًا أولًا.','error');return;}
    if(!stepUp){status('Step-Up مطلوب لتعديل Grants.','error');return;}
    try{await api('/api/database-access/grants',{method:'PUT',...jsonBody({db_name:db,username,privileges})});status(privileges.length?'تم تطبيق صلاحيات MariaDB المحددة.':'تم سحب صلاحيات هذه القاعدة.','ok');await load();}
    catch(err){status(err.status===428?'انتهت نافذة Step-Up.':err.message,'error');}
  }

  $('#databaseGrantForm')?.addEventListener('submit',event=>{
    event.preventDefault();
    const values=[...($('#databaseGrantPrivileges')?.selectedOptions||[])].map(x=>x.value);
    if(!values.length){status('حدد صلاحية واحدة على الأقل، أو استخدم زر سحب الصلاحيات.','error');return;}
    applyGrant(values);
  });
  $('#databaseGrantRevoke')?.addEventListener('click',()=>applyGrant([]));

  $('#databasePasswordForm')?.addEventListener('submit',async event=>{
    event.preventDefault();
    if(!stepUp){status('Step-Up مطلوب لتدوير كلمة المرور.','error');return;}
    const fd=new FormData(event.currentTarget);const username=String(fd.get('username')||'');const password=String(fd.get('password')||'');
    if(!username)return;
    try{await api(`/api/database-access/users/${encodeURIComponent(username)}/password`,{method:'PUT',...jsonBody({password})});event.currentTarget.reset();status('تم تدوير كلمة المرور؛ لم تُحفظ في SQLite أو Audit.','ok');await load();}
    catch(err){status(err.status===428?'انتهت نافذة Step-Up.':err.message,'error');}
  });

  $('#databaseAccessUsers')?.addEventListener('click',async event=>{
    const btn=event.target.closest('[data-db-user-delete]');if(!btn)return;
    if(!stepUp){status('Step-Up مطلوب لحذف المستخدم.','error');return;}
    try{await api(`/api/database-access/users/${encodeURIComponent(btn.dataset.dbUserDelete)}`,{method:'DELETE'});status('تم حذف Database User بعد التأكد من عدم وجود Grants.','ok');await load();}
    catch(err){status(err.message,'error');}
  });

  $('#databaseAccessGrants')?.addEventListener('click',event=>{
    const btn=event.target.closest('[data-db-grant-edit]');if(!btn)return;
    const db=btn.dataset.dbGrantEdit||'';const username=btn.dataset.dbGrantUser||'';
    const grant=state.grants.find(x=>x.db_name===db&&x.db_user===username);if(!grant)return;
    if($('#databaseGrantDb'))$('#databaseGrantDb').value=db;
    if($('#databaseGrantUser'))$('#databaseGrantUser').value=username;
    const selected=new Set(grant.privileges||[]);
    for(const option of $('#databaseGrantPrivileges')?.options||[]) option.selected=selected.has(option.value);
    $('#databaseGrantForm')?.scrollIntoView({behavior:'smooth',block:'center'});
  });

  load();
})();

(()=>{
  const root=document.getElementById('databaseLifecycleManager');
  if(!root)return;
  const csrf=document.querySelector('meta[name="csrf-token"]')?.content||'';
  const stepUp=root.dataset.stepUp==='1';
  const role=root.dataset.role||'viewer';
  const $=s=>root.querySelector(s);
  const esc=v=>String(v??'').replace(/[&<>'"]/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[ch]));
  const state={databases:[],snapshots:[]};
  const bytes=n=>{let v=Number(n||0);for(const u of ['B','KB','MB','GB','TB']){if(v<1024||u==='TB')return`${v.toFixed(v>=10||u==='B'?0:1)} ${u}`;v/=1024;}return'0 B';};
  const when=ts=>ts?new Date(Number(ts)*1000).toLocaleString():'—';
  function status(message,type=''){
    const node=$('#databaseLifecycleStatus');if(!node)return;
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
  function renderDatabaseOptions(){
    const engine=$('#databaseSnapshotEngine')?.value||'mariadb';const select=$('#databaseSnapshotDb');if(!select)return;
    const rows=state.databases.filter(x=>x.engine===engine);
    select.innerHTML='<option value="">اختر قاعدة…</option>'+rows.map(x=>`<option value="${esc(x.db_name)}">${esc(x.db_name)} · ${esc(x.owner)}</option>`).join('');
  }
  function renderSnapshots(){
    const target=$('#databaseSnapshotList');if(!target)return;
    $('#databaseSnapshotCount').textContent=String(state.snapshots.length);
    if(!state.snapshots.length){target.innerHTML='<div class="empty-state">لا توجد Managed Snapshots بعد.</div>';return;}
    target.innerHTML=state.snapshots.map(row=>{
      const hash=String(row.sha256||'');const actions=role==='viewer'?'':`<div class="database-snapshot-actions"><button type="button" class="ghost" data-db-snapshot-restore="${row.id}" ${stepUp?'':'disabled'}>Restore</button><button type="button" class="ghost danger-soft" data-db-snapshot-delete="${row.id}" ${stepUp?'':'disabled'}>حذف</button></div>`;
      return `<article class="database-snapshot-row"><div class="snapshot-engine">${esc(row.engine)}</div><div class="snapshot-copy"><b>${esc(row.db_name)}</b><small>${esc(row.kind)} · ${bytes(row.size_bytes)} · ${when(row.created_at)}</small><code title="${esc(hash)}">SHA-256 ${esc(hash.slice(0,16))}${hash.length>16?'…':''}</code>${row.restored_at?`<small class="restored-mark">آخر Restore: ${when(row.restored_at)}</small>`:''}</div>${actions}</article>`;
    }).join('');
  }
  function render(data){
    state.databases=data.databases||[];state.snapshots=data.snapshots||[];
    const q=data.quota||{};$('#databaseSnapshotQuota').textContent=`${Number(q.used||0)}/${Number(q.limit||0)}`;
    renderDatabaseOptions();renderSnapshots();
  }
  async function load(){try{render(await api('/api/database-lifecycle'));}catch(err){status(`تعذر تحميل Database Lifecycle: ${err.message}`,'error');}}
  $('#databaseSnapshotEngine')?.addEventListener('change',renderDatabaseOptions);
  $('#databaseSnapshotForm')?.addEventListener('submit',async event=>{
    event.preventDefault();if(!stepUp){status('Step-Up مطلوب لإنشاء Snapshot.','error');return;}
    const engine=$('#databaseSnapshotEngine')?.value||'';const db_name=$('#databaseSnapshotDb')?.value||'';if(!db_name)return;
    status('جارٍ إنشاء Snapshot داخل الـAgent…');
    try{await api('/api/database-lifecycle/snapshots',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({engine,db_name})});status('تم إنشاء Managed Snapshot والتحقق من SHA-256.','ok');await load();}
    catch(err){status(err.status===428?'انتهت نافذة Step-Up؛ أعد التحقق.':err.message,'error');}
  });
  $('#databaseSnapshotList')?.addEventListener('click',async event=>{
    const restore=event.target.closest('[data-db-snapshot-restore]');const remove=event.target.closest('[data-db-snapshot-delete]');
    if(!restore&&!remove)return;if(!stepUp){status('Step-Up مطلوب لهذه العملية.','error');return;}
    const id=restore?.dataset.dbSnapshotRestore||remove?.dataset.dbSnapshotDelete;if(!id)return;
    if(restore){
      if(!window.confirm('سيتم أخذ Safety Snapshot أولًا ثم استعادة هذه النسخة. هل تريد المتابعة؟'))return;
      status('جارٍ إنشاء Safety Snapshot وتنفيذ Restore…');
      try{await api(`/api/database-lifecycle/snapshots/${id}/restore`,{method:'POST'});status('اكتملت الاستعادة وتم تسجيل Safety Snapshot للرجوع.','ok');await load();}
      catch(err){status(err.status===428?'انتهت نافذة Step-Up.':err.message,'error');}
    }else{
      if(!window.confirm('حذف ملف Snapshot المُدار؟'))return;
      try{await api(`/api/database-lifecycle/snapshots/${id}`,{method:'DELETE'});status('تم حذف Snapshot من الـStateDirectory والـmetadata.','ok');await load();}
      catch(err){status(err.message,'error');}
    }
  });
  load();
})();
