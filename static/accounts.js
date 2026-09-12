(()=>{
  const root=document.getElementById('accounts');
  if(!root)return;
  const csrf=document.querySelector('meta[name="csrf-token"]')?.content||'';
  const form=document.getElementById('hostingAccountForm');
  const username=document.getElementById('accountUsername');
  const domain=document.getElementById('accountDomain');
  const password=document.getElementById('accountPassword');
  const packageSelect=document.getElementById('accountPackage');
  const list=document.getElementById('accountList');
  const limit=document.getElementById('accountLimit');
  const status=document.getElementById('accountStatus');
  const resellerForm=document.getElementById('resellerForm');
  const resellerList=document.getElementById('resellerList');
  let accounts=[];let packages=[];let resellers=[];

  const say=(msg,kind='')=>{if(!status)return;status.textContent=msg||'';status.className=`account-status ${kind}`.trim();};
  const api=async(url,opts={})=>{const headers={...(opts.headers||{})};if(opts.method&&opts.method!=='GET')headers['X-CSRF-Token']=csrf;if(opts.body&&!headers['Content-Type'])headers['Content-Type']='application/json';const r=await fetch(url,{credentials:'same-origin',...opts,headers});let body={};try{body=await r.json();}catch{}if(!r.ok)throw new Error(body.error||`HTTP ${r.status}`);return body;};
  const btn=(text,action,user,cls='ghost')=>{const b=document.createElement('button');b.type='button';b.className=cls;b.dataset.action=action;b.dataset.user=user;b.textContent=text;return b;};
  const packageOptions=(selected)=>{const s=document.createElement('select');s.dataset.action='package';for(const p of packages){const o=document.createElement('option');o.value=String(p.id);o.textContent=p.name;if(p.id===selected)o.selected=true;s.append(o);}return s;};

  function renderAccounts(){
    list.replaceChildren();
    if(!accounts.length){const e=document.createElement('div');e.className='empty-state';e.textContent='لا توجد Hosting Accounts حتى الآن.';list.append(e);return;}
    for(const a of accounts){const row=document.createElement('div');row.className='account-row';row.dataset.user=a.username;
      const main=document.createElement('div');main.className='account-main';const s=document.createElement('strong');s.textContent=a.username;const x=document.createElement('span');x.textContent=`${a.primary_domain} · ${a.reseller_owner}`;main.append(s,x);
      const meta=document.createElement('div');meta.className='account-meta';const sm=document.createElement('small');sm.textContent=a.package_name;const st=document.createElement('b');st.className=a.status;st.textContent=a.status.toUpperCase();meta.append(sm,st);
      const acts=document.createElement('div');acts.className='account-actions';acts.append(packageOptions(a.package_id),btn(a.status==='active'?'تعليق الدخول':'إعادة التفعيل','status',a.username,a.status==='active'?'tiny danger':'tiny royal-action'));row.append(main,meta,acts);list.append(row);}
  }
  function renderPackages(){packageSelect.replaceChildren();for(const p of packages){const o=document.createElement('option');o.value=String(p.id);o.textContent=p.name;packageSelect.append(o);}if(!packages.length){const o=document.createElement('option');o.textContent='لا توجد حزم متاحة';o.value='';packageSelect.append(o);}}
  function renderResellers(){if(!resellerList)return;resellerList.replaceChildren();if(!resellers.length){const e=document.createElement('div');e.className='empty-state';e.textContent='لا يوجد موزعون حتى الآن.';resellerList.append(e);return;}for(const r of resellers){const row=document.createElement('div');row.className='reseller-row';const main=document.createElement('div');const strong=document.createElement('strong');strong.textContent=r.username;const span=document.createElement('span');span.textContent=`${r.accounts} / ${r.max_accounts} حساب`;main.append(strong,span);const state=document.createElement('span');state.textContent=r.enabled?'ACTIVE':'DISABLED';const b=btn(r.enabled?'تعطيل':'تفعيل','reseller-status',r.username,r.enabled?'tiny danger':'tiny royal-action');b.dataset.max=String(r.max_accounts);row.append(main,state,b);resellerList.append(row);}}
  async function load(){try{const body=await api('/api/accounts');accounts=body.accounts||[];packages=body.packages||[];limit.textContent=`${accounts.length} / ${body.account_limit??'—'}`;renderPackages();renderAccounts();if(resellerList){const rb=await api('/api/resellers');resellers=rb.resellers||[];renderResellers();}}catch(e){say(e.message,'error');}}

  form?.addEventListener('submit',async(e)=>{e.preventDefault();say('جاري إنشاء Hosting Account…');try{await api('/api/accounts',{method:'POST',body:JSON.stringify({username:username.value.trim(),primary_domain:domain.value.trim().toLowerCase(),package_id:Number(packageSelect.value),password:password.value})});form.reset();say('تم إنشاء الحساب وربطه بالحزمة.','ok');await load();}catch(err){say(err.message.includes('step-up')?'يلزم Step-Up Authentication من صفحة الأمن أولًا.':err.message,'error');}});
  list?.addEventListener('change',async(e)=>{const sel=e.target.closest('select[data-action="package"]');if(!sel)return;const row=sel.closest('.account-row');const user=row?.dataset.user;if(!user)return;sel.disabled=true;try{await api(`/api/accounts/${encodeURIComponent(user)}/package`,{method:'PUT',body:JSON.stringify({package_id:Number(sel.value)})});say('تم تحديث حزمة الحساب.','ok');await load();}catch(err){say(err.message,'error');sel.disabled=false;}});
  list?.addEventListener('click',async(e)=>{const b=e.target.closest('button[data-action="status"]');if(!b)return;const a=accounts.find(x=>x.username===b.dataset.user);if(!a)return;b.disabled=true;const next=a.status==='active'?'suspended':'active';try{const body=await api(`/api/accounts/${encodeURIComponent(a.username)}/status`,{method:'PUT',body:JSON.stringify({status:next})});say(body.scope==='control-plane'?'تم تحديث وصول الحساب داخل لوحة التحكم.':'تم تحديث الحساب.','ok');await load();}catch(err){say(err.message,'error');b.disabled=false;}});
  resellerForm?.addEventListener('submit',async(e)=>{e.preventDefault();const u=document.getElementById('resellerUsername');const p=document.getElementById('resellerPassword');const m=document.getElementById('resellerMaxAccounts');say('جاري إنشاء الموزع…');try{await api('/api/resellers',{method:'POST',body:JSON.stringify({username:u.value.trim(),password:p.value,max_accounts:Number(m.value)})});resellerForm.reset();m.value='25';say('تم إنشاء Reseller بحدود مستقلة.','ok');await load();}catch(err){say(err.message,'error');}});
  resellerList?.addEventListener('click',async(e)=>{const b=e.target.closest('button[data-action="reseller-status"]');if(!b)return;const r=resellers.find(x=>x.username===b.dataset.user);if(!r)return;b.disabled=true;try{await api(`/api/resellers/${encodeURIComponent(r.username)}`,{method:'PUT',body:JSON.stringify({enabled:!r.enabled,max_accounts:r.max_accounts})});say('تم تحديث حالة الموزع.','ok');await load();}catch(err){say(err.message,'error');b.disabled=false;}});
  load();
})();
