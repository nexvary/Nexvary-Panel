(()=>{
  const root=document.getElementById('wordpress');if(!root)return;
  const $=s=>root.querySelector(s);const csrf=document.querySelector('meta[name="csrf-token"]')?.content||'';const stepUp=root.dataset.stepUp==='1';
  const result=$('#wpLifecycleResult');const components=$('#wpLifecycleComponents');
  const api=async(url,opt={})=>{const headers={Accept:'application/json',...(opt.headers||{})};if(opt.method&&opt.method!=='GET')headers['X-CSRF-Token']=csrf;if(opt.body&&!headers['Content-Type'])headers['Content-Type']='application/json';const response=await fetch(url,{credentials:'same-origin',...opt,headers});let body={};try{body=await response.json()}catch{}if(!response.ok)throw Object.assign(new Error(body.error||`HTTP ${response.status}`),{status:response.status});return body};
  const domain=()=>$('#wpLifecycleDomain')?.value||'';
  const text=(node,value)=>{if(node)node.textContent=String(value??'—')};
  function clearComponents(){if(components)components.replaceChildren()}
  function componentCard(kind,item){const card=document.createElement('article');card.className='wp-card';const title=document.createElement('b');title.textContent=item.slug||'unknown';const meta=document.createElement('small');meta.textContent=`${kind.toUpperCase()} · ${item.version||'version unknown'}`;card.append(title,meta);return card}
  function renderInventory(data){
    text($('#wpCoreVersion'),data.version||'—');text($('#wpPluginCount'),data.plugin_count??0);text($('#wpThemeCount'),data.theme_count??0);text($('#wpMaintenanceState'),data.maintenance?'MAINTENANCE':'LIVE');
    text($('#wpProviderBadge'),'AGENT ONLINE');
    result.textContent=`${data.domain}\nWordPress ${data.version||'unknown'} · ${data.maintenance?'maintenance':'active'}\nwp-config: ${data.config_present?'present':'not detected'}\nPlugins: ${data.plugin_count||0} · Themes: ${data.theme_count||0}`;
    clearComponents();(data.plugins||[]).slice(0,80).forEach(x=>components.append(componentCard('plugin',x)));(data.themes||[]).slice(0,40).forEach(x=>components.append(componentCard('theme',x)));
  }
  async function inventory(){const d=domain();if(!d)throw new Error('اختر موقع WordPress أولًا');const data=await api(`/api/wordpress/lifecycle?domain=${encodeURIComponent(d)}`);renderInventory(data);return data}
  $('#wpLifecycleDomain')?.addEventListener('change',()=>{clearComponents();if(domain())inventory().catch(e=>{result.textContent=e.message;text($('#wpProviderBadge'),'AGENT OFFLINE')})});
  $('#wpInventoryBtn')?.addEventListener('click',()=>inventory().catch(e=>{result.textContent=e.message;text($('#wpProviderBadge'),'UNAVAILABLE')}));
  $('#wpIntegrityBtn')?.addEventListener('click',async()=>{try{const d=domain();if(!d)throw new Error('اختر موقع WordPress أولًا');result.textContent='جاري التحقق من WordPress Core checksums الرسمية…';const data=await api('/api/wordpress/integrity',{method:'POST',body:JSON.stringify({domain:d})});const missing=data.missing||[],mismatch=data.mismatched||[];result.textContent=`CORE INTEGRITY: ${data.integrity_ok?'PASS':'ATTENTION'}\nVersion: ${data.version}\nChecked: ${data.checked}\nMissing: ${missing.length}\nMismatched: ${mismatch.length}\nSource: ${data.source}${missing.length?`\nMissing files: ${missing.slice(0,20).join(', ')}`:''}${mismatch.length?`\nChanged files: ${mismatch.slice(0,20).join(', ')}`:''}`;text($('#wpProviderBadge'),data.integrity_ok?'INTEGRITY PASS':'ATTENTION')}catch(e){result.textContent=e.message;text($('#wpProviderBadge'),'CHECK FAILED')}});
  async function maintenance(enabled){try{if(!stepUp)throw Object.assign(new Error('Step-Up مطلوب لتغيير Maintenance Mode.'),{status:428});const d=domain();if(!d)throw new Error('اختر موقع WordPress أولًا');await api('/api/wordpress/maintenance',{method:'PUT',body:JSON.stringify({domain:d,enabled})});text($('#wpMaintenanceState'),enabled?'MAINTENANCE':'LIVE');result.textContent=`${d}: Maintenance Mode ${enabled?'ENABLED':'DISABLED'}.`;await inventory()}catch(e){result.textContent=e.status===428?'Step-Up مطلوب من Security قبل تغيير Maintenance Mode.':e.message}}
  $('#wpMaintenanceOnBtn')?.addEventListener('click',()=>maintenance(true));$('#wpMaintenanceOffBtn')?.addEventListener('click',()=>maintenance(false));
})();
