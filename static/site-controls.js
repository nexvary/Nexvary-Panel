(()=>{
  const root=document.getElementById('sitecontrols');
  if(!root)return;
  const csrf=document.querySelector('meta[name="csrf-token"]')?.content||'';
  const stepUp=root.dataset.stepUp==='1';
  const $=sel=>root.querySelector(sel);
  const status=(msg,type='')=>{const node=$('#siteControlNotice');if(!node)return;node.textContent=msg||'';node.className=`sitecontrols-status ${type}`.trim();};
  const api=async(url,options={})=>{
    const opts={credentials:'same-origin',...options,headers:{Accept:'application/json',...(options.headers||{})}};
    if(opts.method&&opts.method!=='GET')opts.headers['X-CSRF-Token']=csrf;
    const res=await fetch(url,opts);let data={};
    try{data=await res.json();}catch{data={ok:false,error:`HTTP ${res.status}`};}
    if(!res.ok||data.ok===false){const err=new Error(data.error||`HTTP ${res.status}`);err.status=res.status;throw err;}
    return data;
  };
  const domain=()=>$('#siteControlDomain')?.value||'';
  const jsonPut=(url,payload)=>api(url,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
  const writeButtons=()=>root.querySelectorAll('form button[type="submit"]');
  let capabilities={};

  function setCapability(formId,capability){
    const form=$(formId);if(!form)return;
    const allowed=Boolean(capabilities[capability]);
    form.querySelectorAll('input,select,textarea,button').forEach(el=>{el.disabled=!allowed||(!stepUp&&el.tagName==='BUTTON');});
    form.dataset.capability=allowed?'1':'0';
  }
  function render(data){
    const s=data.settings||{};capabilities=data.capabilities||{};
    $('#scPrivacyState').textContent=s.privacy_enabled?'ON':'OFF';
    $('#scHotlinkState').textContent=s.hotlink_enabled?'ON':'OFF';
    $('#scIndexState').textContent=String(s.indexing_mode||'off').toUpperCase();
    $('#scMimeCount').textContent=String(Object.keys(s.mime_overrides||{}).length);
    const privacy=$('#privacyControlForm');
    privacy.elements.enabled.checked=Boolean(s.privacy_enabled);
    privacy.elements.path.value=s.privacy_path||'/';
    privacy.elements.username.value=s.privacy_username||'';
    privacy.elements.password.value='';
    const hotlink=$('#hotlinkControlForm');
    hotlink.elements.enabled.checked=Boolean(s.hotlink_enabled);
    hotlink.elements.extensions.value=(s.hotlink_extensions||[]).join(',');
    $('#indexControlForm').elements.mode.value=s.indexing_mode||'off';
    $('#mimeControlForm').elements.mappings.value=Object.entries(s.mime_overrides||{}).map(([ext,mime])=>`${ext} ${mime}`).join('\n');
    setCapability('#privacyControlForm','directory_privacy');
    setCapability('#hotlinkControlForm','hotlink');
    setCapability('#indexControlForm','indexes');
    setCapability('#mimeControlForm','mime_types');
    $('#refreshRawAccess').disabled=!capabilities.raw_access;
  }
  async function loadSettings(){
    const value=domain();
    if(!value){status('اختر موقعًا لعرض Site Controls.');return;}
    try{const data=await api(`/api/site-controls?domain=${encodeURIComponent(value)}`);render(data);status('تم تحميل سياسة الموقع.','ok');if(capabilities.raw_access)await loadRaw();}
    catch(err){status(err.message,'error');}
  }
  async function loadSites(){
    const data=await api('/api/webtools/sites');const select=$('#siteControlDomain');const sites=data.sites||[];
    select.innerHTML='<option value="">اختر موقعًا…</option>'+sites.map(s=>`<option value="${String(s.domain).replace(/"/g,'&quot;')}">${String(s.domain)}</option>`).join('');
    if(sites.length){select.value=sites[0].domain;await loadSettings();}else status('لا توجد مواقع مسجلة لإدارة Site Controls.');
  }
  async function loadRaw(){
    const value=domain();if(!value||!capabilities.raw_access)return;
    const lines=Number($('#rawAccessLines').value||200);
    const output=$('#rawAccessOutput');output.textContent='Loading…';
    try{const data=await api(`/api/site-controls/raw-access?domain=${encodeURIComponent(value)}&lines=${lines}`);output.textContent=(data.lines||[]).join('\n')||'لا توجد طلبات في نافذة السجل الحالية.';if(data.truncated)status('Raw Access يعرض نافذة محدودة من أحدث السجل.','ok');}
    catch(err){output.textContent=`Unavailable: ${err.message}`;}
  }
  $('#siteControlDomain')?.addEventListener('change',loadSettings);
  $('#refreshRawAccess')?.addEventListener('click',loadRaw);
  $('#rawAccessLines')?.addEventListener('change',loadRaw);

  $('#privacyControlForm')?.addEventListener('submit',async event=>{
    event.preventDefault();if(!stepUp){status('Step-Up مطلوب قبل تعديل NGINX.','error');return;}
    const f=event.currentTarget.elements,payload={domain:domain(),enabled:f.enabled.checked,path:f.path.value,username:f.username.value,password:f.password.value};
    try{const data=await jsonPut('/api/site-controls/privacy',payload);render({settings:data.settings,capabilities});status('تم تطبيق Directory Privacy بعد التحقق من NGINX.','ok');}
    catch(err){status(err.status===428?'انتهت نافذة Step-Up؛ أعد التحقق من Security.':err.message,'error');}
  });
  $('#hotlinkControlForm')?.addEventListener('submit',async event=>{
    event.preventDefault();if(!stepUp){status('Step-Up مطلوب.','error');return;}
    const f=event.currentTarget.elements,extensions=String(f.extensions.value||'').split(',').map(v=>v.trim()).filter(Boolean);
    try{const data=await jsonPut('/api/site-controls/hotlink',{domain:domain(),enabled:f.enabled.checked,extensions});render({settings:data.settings,capabilities});status('تم تطبيق Hotlink Protection.','ok');}
    catch(err){status(err.message,'error');}
  });
  $('#indexControlForm')?.addEventListener('submit',async event=>{
    event.preventDefault();if(!stepUp){status('Step-Up مطلوب.','error');return;}
    try{const data=await jsonPut('/api/site-controls/indexing',{domain:domain(),mode:event.currentTarget.elements.mode.value});render({settings:data.settings,capabilities});status('تم تحديث Directory Indexing.','ok');}
    catch(err){status(err.message,'error');}
  });
  $('#mimeControlForm')?.addEventListener('submit',async event=>{
    event.preventDefault();if(!stepUp){status('Step-Up مطلوب.','error');return;}
    const mappings={};
    for(const raw of String(event.currentTarget.elements.mappings.value||'').split(/\r?\n/)){
      const line=raw.trim();if(!line)continue;const parts=line.split(/\s+/);if(parts.length!==2){status(`سطر MIME غير صالح: ${line}`,'error');return;}mappings[parts[0]]=parts[1];
    }
    try{const data=await jsonPut('/api/site-controls/mime',{domain:domain(),mappings});render({settings:data.settings,capabilities});status('تم تطبيق MIME Overrides.','ok');}
    catch(err){status(err.message,'error');}
  });
  writeButtons().forEach(button=>{if(!stepUp)button.title='Step-Up required';});
  loadSites().catch(err=>status(`تعذر تحميل Site Control Center: ${err.message}`,'error'));
})();
