(()=>{
  const root=document.getElementById('wordpress');if(!root)return;
  const $=s=>root.querySelector(s);const csrf=document.querySelector('meta[name="csrf-token"]')?.content||'';const stepUp=root.dataset.stepUp==='1';
  const result=$('#wpLifecycleResult');const components=$('#wpLifecycleComponents');let coreSnapshot='';const componentSnapshots=new Map();
  const api=async(url,opt={})=>{const headers={Accept:'application/json',...(opt.headers||{})};if(opt.method&&opt.method!=='GET')headers['X-CSRF-Token']=csrf;if(opt.body&&!headers['Content-Type'])headers['Content-Type']='application/json';const response=await fetch(url,{credentials:'same-origin',...opt,headers});let body={};try{body=await response.json()}catch{}if(!response.ok)throw Object.assign(new Error(body.error||`HTTP ${response.status}`),{status:response.status});return body};
  const domain=()=>$('#wpLifecycleDomain')?.value||'';
  const text=(node,value)=>{if(node)node.textContent=String(value??'—')};
  const actionButton=(label,cls,handler)=>{const b=document.createElement('button');b.type='button';b.className=cls;b.textContent=label;b.addEventListener('click',handler);return b};
  const snapshotKey=(kind,slug)=>`${domain()}|${kind}|${slug}`;
  function clearComponents(){if(components)components.replaceChildren()}

  async function checkComponent(kind,item,card){
    const d=domain();if(!d)throw new Error('اختر موقع WordPress أولًا');
    const data=await api(`/api/wordpress/components/check?domain=${encodeURIComponent(d)}&kind=${encodeURIComponent(kind)}&slug=${encodeURIComponent(item.slug)}`);
    const status=card.querySelector('[data-component-status]');if(status)status.textContent=data.update_available?`UPDATE ${data.installed_version||'?'} → ${data.latest_version}`:`CURRENT ${data.latest_version||data.installed_version||'unknown'}`;
    result.textContent=`${kind.toUpperCase()} ${item.slug}\nInstalled: ${data.installed_version||'unknown'}\nOfficial latest: ${data.latest_version||'unknown'}\nUpdate: ${data.update_available?'AVAILABLE':'NOT REQUIRED'}\nSource: ${data.source}`;
    return data;
  }

  async function updateComponent(kind,item,card){
    try{
      if(!stepUp)throw Object.assign(new Error('Step-Up مطلوب لتحديث WordPress Components.'),{status:428});
      const d=domain();if(!d)throw new Error('اختر موقع WordPress أولًا');
      result.textContent=`جاري تحديث ${kind} ${item.slug} من WordPress.org مع Snapshot…`;
      const data=await api('/api/wordpress/components/update',{method:'POST',body:JSON.stringify({domain:d,kind,slug:item.slug})});
      if(data.snapshot_id)componentSnapshots.set(snapshotKey(kind,item.slug),data.snapshot_id);
      result.textContent=data.updated?`${kind.toUpperCase()} ${item.slug}: ${data.installed_version||'?'} → ${data.latest_version||'?'}\nSnapshot: ${data.snapshot_id}\nSource: ${data.source||'downloads.wordpress.org'}`:`${kind.toUpperCase()} ${item.slug}: لا يوجد تحديث مطلوب (${data.latest_version||data.installed_version||'current'}).`;
      await inventory();
    }catch(e){result.textContent=e.status===428?'Step-Up مطلوب من Security قبل تحديث Plugin/Theme.':e.message}
  }

  async function rollbackComponent(kind,item){
    try{
      if(!stepUp)throw Object.assign(new Error('Step-Up مطلوب لعمل Rollback.'),{status:428});
      const d=domain();const snapshotId=componentSnapshots.get(snapshotKey(kind,item.slug));if(!snapshotId)throw new Error('لا يوجد Snapshot محفوظ لهذا Component في الجلسة الحالية.');
      const data=await api('/api/wordpress/components/rollback',{method:'POST',body:JSON.stringify({domain:d,snapshot_id:snapshotId})});
      result.textContent=`ROLLBACK ${data.kind?.toUpperCase()||kind.toUpperCase()} ${data.slug||item.slug}\nRestored: ${data.restored_version||'previous version'}\nSnapshot: ${snapshotId}`;
      await inventory();
    }catch(e){result.textContent=e.status===428?'Step-Up مطلوب من Security قبل Rollback.':e.message}
  }

  function componentCard(kind,item){
    const card=document.createElement('article');card.className='wp-card';
    const title=document.createElement('b');title.textContent=item.slug||'unknown';
    const meta=document.createElement('small');meta.textContent=`${kind.toUpperCase()} · ${item.version||'version unknown'}`;
    const state=document.createElement('small');state.dataset.componentStatus='1';state.textContent='UPDATE STATUS · NOT CHECKED';
    const actions=document.createElement('div');actions.className='adv-inline';
    actions.append(actionButton('Check Update','tiny ghost',()=>checkComponent(kind,item,card).catch(e=>{result.textContent=e.message})));
    const update=actionButton('Update','tiny danger',()=>updateComponent(kind,item,card));update.disabled=!stepUp;actions.append(update);
    const rollback=actionButton('Rollback','tiny ghost',()=>rollbackComponent(kind,item));rollback.disabled=!stepUp||!componentSnapshots.has(snapshotKey(kind,item.slug));actions.append(rollback);
    card.append(title,meta,state,actions);return card;
  }

  function renderInventory(data){
    text($('#wpCoreVersion'),data.version||'—');text($('#wpPluginCount'),data.plugin_count??0);text($('#wpThemeCount'),data.theme_count??0);text($('#wpMaintenanceState'),data.maintenance?'MAINTENANCE':'LIVE');
    text($('#wpProviderBadge'),'AGENT ONLINE');
    result.textContent=`${data.domain}\nWordPress ${data.version||'unknown'} · ${data.maintenance?'maintenance':'active'}\nwp-config: ${data.config_present?'present':'not detected'}\nPlugins: ${data.plugin_count||0} · Themes: ${data.theme_count||0}`;
    clearComponents();(data.plugins||[]).slice(0,80).forEach(x=>components.append(componentCard('plugin',x)));(data.themes||[]).slice(0,40).forEach(x=>components.append(componentCard('theme',x)));
  }
  async function inventory(){const d=domain();if(!d)throw new Error('اختر موقع WordPress أولًا');const data=await api(`/api/wordpress/lifecycle?domain=${encodeURIComponent(d)}`);renderInventory(data);return data}
  $('#wpLifecycleDomain')?.addEventListener('change',()=>{coreSnapshot='';clearComponents();if(domain())inventory().catch(e=>{result.textContent=e.message;text($('#wpProviderBadge'),'AGENT OFFLINE')})});
  $('#wpInventoryBtn')?.addEventListener('click',()=>inventory().catch(e=>{result.textContent=e.message;text($('#wpProviderBadge'),'UNAVAILABLE')}));
  $('#wpIntegrityBtn')?.addEventListener('click',async()=>{try{const d=domain();if(!d)throw new Error('اختر موقع WordPress أولًا');result.textContent='جاري التحقق من WordPress Core checksums الرسمية…';const data=await api('/api/wordpress/integrity',{method:'POST',body:JSON.stringify({domain:d})});const missing=data.missing||[],mismatch=data.mismatched||[];result.textContent=`CORE INTEGRITY: ${data.integrity_ok?'PASS':'ATTENTION'}\nVersion: ${data.version}\nChecked: ${data.checked}\nMissing: ${missing.length}\nMismatched: ${mismatch.length}\nSource: ${data.source}${missing.length?`\nMissing files: ${missing.slice(0,20).join(', ')}`:''}${mismatch.length?`\nChanged files: ${mismatch.slice(0,20).join(', ')}`:''}`;text($('#wpProviderBadge'),data.integrity_ok?'INTEGRITY PASS':'ATTENTION')}catch(e){result.textContent=e.message;text($('#wpProviderBadge'),'CHECK FAILED')}});

  $('#wpRepairBtn')?.addEventListener('click',async()=>{try{if(!stepUp)throw Object.assign(new Error('Step-Up مطلوب لإصلاح WordPress Core.'),{status:428});const d=domain();if(!d)throw new Error('اختر موقع WordPress أولًا');result.textContent='جاري إنشاء Snapshot ثم إصلاح ملفات WordPress Core التالفة فقط…';const data=await api('/api/wordpress/repair-core',{method:'POST',body:JSON.stringify({domain:d})});coreSnapshot=data.snapshot_id||'';const rollback=$('#wpRollbackBtn');if(rollback)rollback.disabled=!coreSnapshot;result.textContent=`CORE REPAIR: ${data.integrity_ok?'PASS':'ATTENTION'}\nVersion: ${data.version||'unknown'}\nRepaired: ${data.repaired||0}\nSnapshot: ${coreSnapshot||'not required'}`;await inventory()}catch(e){result.textContent=e.status===428?'Step-Up مطلوب من Security قبل Core Repair.':e.message}});
  $('#wpRollbackBtn')?.addEventListener('click',async()=>{try{if(!stepUp)throw Object.assign(new Error('Step-Up مطلوب للRollback.'),{status:428});const d=domain();if(!d||!coreSnapshot)throw new Error('لا يوجد Core Repair Snapshot في الجلسة الحالية.');const data=await api('/api/wordpress/repair-rollback',{method:'POST',body:JSON.stringify({domain:d,snapshot_id:coreSnapshot})});result.textContent=`CORE ROLLBACK: restored ${data.rolled_back||0} files\nSnapshot: ${coreSnapshot}`;await inventory()}catch(e){result.textContent=e.status===428?'Step-Up مطلوب من Security قبل Core Rollback.':e.message}});

  async function maintenance(enabled){try{if(!stepUp)throw Object.assign(new Error('Step-Up مطلوب لتغيير Maintenance Mode.'),{status:428});const d=domain();if(!d)throw new Error('اختر موقع WordPress أولًا');await api('/api/wordpress/maintenance',{method:'PUT',body:JSON.stringify({domain:d,enabled})});text($('#wpMaintenanceState'),enabled?'MAINTENANCE':'LIVE');result.textContent=`${d}: Maintenance Mode ${enabled?'ENABLED':'DISABLED'}.`;await inventory()}catch(e){result.textContent=e.status===428?'Step-Up مطلوب من Security قبل تغيير Maintenance Mode.':e.message}}
  $('#wpMaintenanceOnBtn')?.addEventListener('click',()=>maintenance(true));$('#wpMaintenanceOffBtn')?.addEventListener('click',()=>maintenance(false));
})();
