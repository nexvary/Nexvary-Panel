(()=>{
  const root=document.getElementById('mail');if(!root)return;
  const csrf=document.querySelector('meta[name="csrf-token"]')?.content||'';
  const $=s=>root.querySelector(s);
  const status=$('#mailAutomationStatus');
  let mailboxId=0;let current=null;let mailboxes=[];
  const say=(msg,kind='')=>{if(!status)return;status.textContent=msg||'';status.className=`mail-status ${kind}`.trim();};
  const api=async(url,opt={})=>{const headers={Accept:'application/json',...(opt.headers||{})};if(opt.method&&opt.method!=='GET')headers['X-CSRF-Token']=csrf;if(opt.body&&!headers['Content-Type'])headers['Content-Type']='application/json';const r=await fetch(url,{credentials:'same-origin',...opt,headers});let b={};try{b=await r.json()}catch{}if(!r.ok)throw Object.assign(new Error(b.error||`HTTP ${r.status}`),{status:r.status});return b;};
  const empty=text=>{const d=document.createElement('div');d.className='empty-state';d.textContent=text;return d;};
  const safeStepError=e=>e.status===428?'يلزم Step-Up Authentication قبل تعديل أتمتة البريد.':e.message;

  function setDisabled(form,disabled){form?.querySelectorAll('input,select,textarea,button').forEach(el=>el.disabled=disabled);}
  function fillMailboxSelector(){
    const select=$('#mailAutomationMailbox');if(!select)return;
    const previous=select.value;select.replaceChildren();
    const active=mailboxes.filter(m=>m.enabled);
    if(!active.length){const o=document.createElement('option');o.value='';o.textContent='لا توجد Mailboxes فعالة';select.append(o);select.disabled=true;mailboxId=0;return;}
    select.disabled=false;
    for(const m of active){const o=document.createElement('option');o.value=String(m.id);o.textContent=`${m.localpart}@${m.domain}`;select.append(o);}
    if(active.some(m=>String(m.id)===previous))select.value=previous;
    mailboxId=Number(select.value||0);
  }
  async function loadMailboxes(){
    const d=await api('/api/mail');mailboxes=d.mailboxes||[];fillMailboxSelector();if(mailboxId)await loadAutomation();else renderEmpty();
  }
  function renderEmpty(){
    current=null;const list=$('#mailFilterList');if(list){list.replaceChildren(empty('اختر Mailbox لعرض الفلاتر.'));}
    $('#mailAutomationFeatureState').textContent='NO MAILBOX';
    setDisabled($('#mailAutoresponderForm'),true);setDisabled($('#mailFilterForm'),true);setDisabled($('#mailSpamForm'),true);
  }
  function render(){
    if(!current)return renderEmpty();
    const f=current.features||{};
    $('#mailAutomationFeatureState').textContent=`AUTO ${f.autoresponders?'ON':'OFF'} · FILTER ${f.filters?'ON':'OFF'} · SPAM ${f.spam_filters?'ON':'OFF'}`;
    const a=current.autoresponder||{};$('#mailAutoresponderEnabled').checked=!!a.enabled;$('#mailAutoresponderDays').value=String(a.interval_days||1);$('#mailAutoresponderSubject').value=a.subject||'';$('#mailAutoresponderBody').value=a.body||'';
    const s=current.spam||{};$('#mailSpamEnabled').checked=!!s.enabled;$('#mailSpamAction').value=s.action||'junk';
    setDisabled($('#mailAutoresponderForm'),!f.autoresponders&&!a.enabled);
    setDisabled($('#mailFilterForm'),!f.filters);
    setDisabled($('#mailSpamForm'),!f.spam_filters&&!s.enabled);
    renderFilters(current.filters||[]);
  }
  function renderFilters(rows){
    const box=$('#mailFilterList');if(!box)return;box.replaceChildren();
    if(!rows.length){box.append(empty('لا توجد فلاتر لهذا الصندوق.'));return;}
    for(const item of rows){
      const r=document.createElement('div');r.className='mail-row automation-row';
      const main=document.createElement('div');main.className='mail-row-main';const title=document.createElement('strong');title.textContent=`${item.field} ${item.match_type} “${item.pattern}”`;const sub=document.createElement('span');sub.textContent=`${item.action}${item.destination?` → ${item.destination}`:''} · priority ${item.priority}`;main.append(title,sub);
      const meta=document.createElement('div');meta.className='mail-row-meta';const state=document.createElement('b');state.textContent=item.enabled?'ACTIVE':'DISABLED';meta.append(state);
      const del=document.createElement('button');del.type='button';del.className='tiny danger';del.textContent='حذف';del.dataset.mailFilterDelete=String(item.id);
      r.append(main,meta,del);box.append(r);
    }
  }
  async function loadAutomation(){
    mailboxId=Number($('#mailAutomationMailbox')?.value||0);if(!mailboxId)return renderEmpty();
    try{current=await api(`/api/mail/automation/${mailboxId}`);render();say('تم تحميل سياسة Mailbox.','ok');}catch(e){current=null;renderEmpty();say(e.message,'error');}
  }
  $('#mailAutomationMailbox')?.addEventListener('change',loadAutomation);
  $('#mailRefresh')?.addEventListener('click',()=>setTimeout(()=>loadMailboxes().catch(e=>say(e.message,'error')),100));

  $('#mailAutoresponderForm')?.addEventListener('submit',async e=>{
    e.preventDefault();if(!mailboxId)return say('اختر Mailbox أولًا.','error');
    try{current=await api(`/api/mail/automation/${mailboxId}/autoresponder`,{method:'PUT',body:JSON.stringify({enabled:$('#mailAutoresponderEnabled').checked,subject:$('#mailAutoresponderSubject').value.trim(),body:$('#mailAutoresponderBody').value,interval_days:Number($('#mailAutoresponderDays').value)})});render();say('تم حفظ Autoresponder وتجميع Sieve بنجاح.','ok');}catch(err){say(safeStepError(err),'error');}
  });
  $('#mailFilterAction')?.addEventListener('change',()=>{
    const a=$('#mailFilterAction').value,d=$('#mailFilterDestination');if(a==='discard'){d.value='';d.disabled=true;d.placeholder='لا توجد وجهة';}else{d.disabled=false;d.placeholder=a==='fileinto'?'Billing':'archive@example.com';}
  });
  $('#mailFilterForm')?.addEventListener('submit',async e=>{
    e.preventDefault();if(!mailboxId)return say('اختر Mailbox أولًا.','error');
    const action=$('#mailFilterAction').value;
    try{current=await api(`/api/mail/automation/${mailboxId}/filters`,{method:'POST',body:JSON.stringify({field:$('#mailFilterField').value,match_type:$('#mailFilterMatch').value,pattern:$('#mailFilterPattern').value.trim(),action,destination:action==='discard'?'':$('#mailFilterDestination').value.trim(),priority:Number($('#mailFilterPriority').value)})});render();e.currentTarget.reset();$('#mailFilterPriority').value='100';$('#mailFilterAction').dispatchEvent(new Event('change'));say('تمت إضافة Filter وإعادة تجميع Sieve.','ok');}catch(err){say(safeStepError(err),'error');}
  });
  $('#mailFilterList')?.addEventListener('click',async e=>{
    const b=e.target.closest('[data-mail-filter-delete]');if(!b)return;b.disabled=true;
    try{current=await api(`/api/mail/automation/filters/${b.dataset.mailFilterDelete}`,{method:'DELETE'});render();say('تم حذف Filter وإعادة تجميع Sieve.','ok');}catch(err){b.disabled=false;say(safeStepError(err),'error');}
  });
  $('#mailSpamForm')?.addEventListener('submit',async e=>{
    e.preventDefault();if(!mailboxId)return say('اختر Mailbox أولًا.','error');
    try{current=await api(`/api/mail/automation/${mailboxId}/spam`,{method:'PUT',body:JSON.stringify({enabled:$('#mailSpamEnabled').checked,action:$('#mailSpamAction').value})});render();say('تم حفظ Spam action policy. تعتمد على X-Spam-Flag من scanner خارجي.','ok');}catch(err){say(safeStepError(err),'error');}
  });
  $('#mailFilterAction')?.dispatchEvent(new Event('change'));
  loadMailboxes().catch(e=>say(`تعذر تحميل Mail Automation: ${e.message}`,'error'));
})();

/* Default Address is a separate policy surface because catch-all changes are domain-wide,
   privileged and deliberately stricter than mailbox-level Sieve automation. */
(()=>{
  const root=document.getElementById('mail');if(!root||root.querySelector('#mailDefaultAddressShell'))return;
  const csrf=document.querySelector('meta[name="csrf-token"]')?.content||'';
  const anchor=root.querySelector('.mail-automation-shell');if(!anchor)return;
  const shell=document.createElement('article');
  shell.id='mailDefaultAddressShell';
  shell.className='panel royal-frame frame-silver mail-default-shell';
  shell.innerHTML=`
    <div class="panel-head">
      <div><span class="kicker">DEFAULT ADDRESS · DOMAIN CATCH-ALL</span><h3>العنوان الافتراضي للنطاق</h3></div>
      <span id="mailDefaultFeatureState" class="mail-chip">POLICY CHECK</span>
    </div>
    <div class="mail-policy-note">الافتراضي الآمن هو Reject. التحويل Catch-all يسمح فقط بوجهة خارج النطاق نفسه لمنع حلقات البريد، ويتطلب Step-Up، ويُطبق عبر Mail Provider مع Rollback وAudit.</div>
    <form id="mailDefaultForm" class="mail-form automation-form" autocomplete="off">
      <label>النطاق<select id="mailDefaultDomain" required><option value="">جاري تحميل النطاقات…</option></select></label>
      <label>السياسة<select id="mailDefaultMode"><option value="reject">Reject unknown recipients</option><option value="forward">Forward catch-all</option></select></label>
      <label class="full-row">وجهة التحويل<input id="mailDefaultDestination" type="email" maxlength="320" autocomplete="off" placeholder="catchall@external.example" disabled></label>
      <button id="mailDefaultSave" class="primary royal-action" type="submit">حفظ Default Address</button>
      <div id="mailDefaultStatus" class="mail-status full-row" role="status" aria-live="polite"></div>
    </form>`;
  anchor.before(shell);

  const domain=shell.querySelector('#mailDefaultDomain');
  const mode=shell.querySelector('#mailDefaultMode');
  const destination=shell.querySelector('#mailDefaultDestination');
  const save=shell.querySelector('#mailDefaultSave');
  const featureState=shell.querySelector('#mailDefaultFeatureState');
  const status=shell.querySelector('#mailDefaultStatus');
  let providerOnline=false;
  let featureAllowed=false;

  const say=(msg,kind='')=>{status.textContent=msg||'';status.className=`mail-status full-row ${kind}`.trim();};
  const api=async(url,opt={})=>{const headers={Accept:'application/json',...(opt.headers||{})};if(opt.method&&opt.method!=='GET')headers['X-CSRF-Token']=csrf;if(opt.body&&!headers['Content-Type'])headers['Content-Type']='application/json';const r=await fetch(url,{credentials:'same-origin',...opt,headers});let b={};try{b=await r.json()}catch{}if(!r.ok)throw Object.assign(new Error(b.error||`HTTP ${r.status}`),{status:r.status});return b;};
  function updateControls(){
    const forward=mode.value==='forward';
    destination.disabled=!forward||!featureAllowed||!providerOnline;
    destination.required=forward;
    save.disabled=!domain.value||!featureAllowed||!providerOnline;
    featureState.textContent=!providerOnline?'PROVIDER OFFLINE':featureAllowed?'FOUNDATION · ACTIVE':'DISABLED BY PACKAGE';
  }
  function modeChanged(){if(mode.value==='reject')destination.value='';updateControls();}
  async function loadPolicy(){
    if(!domain.value){featureAllowed=false;updateControls();return;}
    say('جاري قراءة سياسة Default Address…');
    try{
      const data=await api(`/api/mail/default-address?domain=${encodeURIComponent(domain.value)}`);
      featureAllowed=!!data.feature_allowed;
      const current=data.default_address||{};
      mode.value=current.mode==='forward'?'forward':'reject';
      destination.value=current.mode==='forward'?(current.destination||''):'';
      updateControls();
      say(featureAllowed?'تم تحميل سياسة العنوان الافتراضي.':'الميزة معطلة في حزمة هذا النطاق.',featureAllowed?'ok':'error');
    }catch(err){featureAllowed=false;updateControls();say(err.message,'error');}
  }
  async function bootstrap(){
    try{
      const data=await api('/api/mail');
      providerOnline=!!data.provider?.online;
      const domains=(data.available_domains||[]).filter(item=>item.email_accounts||item.email_forwarders);
      domain.replaceChildren();
      if(!domains.length){const option=document.createElement('option');option.value='';option.textContent='لا توجد نطاقات بريد ضمن نطاقك';domain.append(option);domain.disabled=true;featureAllowed=false;updateControls();say('لا توجد نطاقات بريد متاحة.','error');return;}
      for(const item of domains){const option=document.createElement('option');option.value=item.domain;option.textContent=item.owner==='admin'?item.domain:`${item.domain} · ${item.owner}`;domain.append(option);}
      domain.disabled=false;
      await loadPolicy();
    }catch(err){providerOnline=false;featureAllowed=false;updateControls();say(`تعذر تحميل Default Address: ${err.message}`,'error');}
  }
  domain.addEventListener('change',loadPolicy);
  mode.addEventListener('change',modeChanged);
  shell.querySelector('#mailDefaultForm').addEventListener('submit',async event=>{
    event.preventDefault();
    if(!providerOnline)return say('Mail Provider غير متصل.','error');
    if(!featureAllowed)return say('email.default_address معطلة في حزمة هذا النطاق.','error');
    const payload={domain:domain.value,mode:mode.value,destination:mode.value==='forward'?destination.value.trim().toLowerCase():''};
    if(payload.mode==='forward'&&payload.destination.endsWith(`@${payload.domain}`))return say('وجهة Catch-all يجب أن تكون خارج النطاق نفسه.','error');
    save.disabled=true;say('جاري تطبيق Default Address عبر Mail Provider…');
    try{
      const result=await api('/api/mail/default-address',{method:'PUT',body:JSON.stringify(payload)});
      const current=result.default_address||payload;
      mode.value=current.mode==='forward'?'forward':'reject';destination.value=current.destination||'';
      say('تم حفظ Default Address والتحقق من سياسة Catch-all.','ok');
    }catch(err){say(err.status===428?'يلزم Step-Up Authentication قبل تعديل Default Address.':err.message,'error');}
    finally{updateControls();}
  });
  modeChanged();bootstrap();
})();

/* Email Routing controls whether Postfix claims a domain as locally delivered mail.
   Remote mode is intentionally conservative: it does not become a generic relay and it
   cannot be enabled while local mail resources still exist for the domain. */
(()=>{
  const root=document.getElementById('mail');if(!root||root.querySelector('#mailRoutingShell'))return;
  const csrf=document.querySelector('meta[name="csrf-token"]')?.content||'';
  const anchor=root.querySelector('#mailDefaultAddressShell')||root.querySelector('.mail-automation-shell');if(!anchor)return;
  const shell=document.createElement('article');
  shell.id='mailRoutingShell';
  shell.className='panel royal-frame frame-electric-black mail-routing-shell';
  shell.innerHTML=`
    <div class="panel-head">
      <div><span class="kicker">EMAIL ROUTING · POSTFIX DOMAIN POLICY</span><h3>مسار البريد للنطاق</h3></div>
      <span id="mailRoutingFeatureState" class="mail-chip">POLICY CHECK</span>
    </div>
    <div class="mail-policy-note">Local Mail Exchanger يجعل Postfix يستقبل البريد لهذا النطاق محليًا. Remote Mail Exchanger يوقف ادعاء النطاق محليًا ويُستخدم فقط عندما يشير MX إلى مزود خارجي. لا تنشئ هذه الميزة Open Relay، ولا تسمح بالتحويل إلى Remote مع وجود Mailboxes أو Forwarders أو Catch-all محلي.</div>
    <form id="mailRoutingForm" class="mail-form automation-form" autocomplete="off">
      <label>النطاق<select id="mailRoutingDomain" required><option value="">جاري تحميل النطاقات…</option></select></label>
      <label>وضع التوجيه<select id="mailRoutingMode"><option value="local">Local Mail Exchanger</option><option value="remote">Remote Mail Exchanger</option></select></label>
      <div id="mailRoutingResourceState" class="mail-policy-note full-row">جاري فحص الموارد المحلية…</div>
      <button id="mailRoutingSave" class="primary royal-action" type="submit">حفظ Email Routing</button>
      <div id="mailRoutingStatus" class="mail-status full-row" role="status" aria-live="polite"></div>
    </form>`;
  anchor.before(shell);

  const domain=shell.querySelector('#mailRoutingDomain');
  const mode=shell.querySelector('#mailRoutingMode');
  const save=shell.querySelector('#mailRoutingSave');
  const featureState=shell.querySelector('#mailRoutingFeatureState');
  const resourceState=shell.querySelector('#mailRoutingResourceState');
  const status=shell.querySelector('#mailRoutingStatus');
  let providerOnline=false;
  let featureAllowed=false;
  let conflicts={mailboxes:0,forwarders:0,catchall_forward:false};

  const say=(msg,kind='')=>{status.textContent=msg||'';status.className=`mail-status full-row ${kind}`.trim();};
  const api=async(url,opt={})=>{const headers={Accept:'application/json',...(opt.headers||{})};if(opt.method&&opt.method!=='GET')headers['X-CSRF-Token']=csrf;if(opt.body&&!headers['Content-Type'])headers['Content-Type']='application/json';const r=await fetch(url,{credentials:'same-origin',...opt,headers});let b={};try{b=await r.json()}catch{}if(!r.ok)throw Object.assign(new Error(b.error||`HTTP ${r.status}`),{status:r.status,body:b});return b;};
  const hasConflicts=()=>Number(conflicts.mailboxes||0)>0||Number(conflicts.forwarders||0)>0||!!conflicts.catchall_forward;
  function updateControls(){
    const remoteBlocked=mode.value==='remote'&&hasConflicts();
    save.disabled=!domain.value||!featureAllowed||!providerOnline||remoteBlocked;
    featureState.textContent=!providerOnline?'PROVIDER OFFLINE':featureAllowed?'FOUNDATION · ACTIVE':'DISABLED BY PACKAGE';
    resourceState.textContent=`Local resources · Mailboxes ${Number(conflicts.mailboxes||0)} · Forwarders ${Number(conflicts.forwarders||0)} · Catch-all ${conflicts.catchall_forward?'FORWARD':'CLEAR'}${remoteBlocked?' · أزلها قبل Remote':''}`;
  }
  async function loadPolicy(){
    if(!domain.value){featureAllowed=false;updateControls();return;}
    say('جاري قراءة Email Routing…');
    try{
      const data=await api(`/api/mail/routing?domain=${encodeURIComponent(domain.value)}`);
      featureAllowed=!!data.feature_allowed;
      conflicts=data.local_resources||conflicts;
      mode.value=data.routing?.mode==='remote'?'remote':'local';
      updateControls();
      say(featureAllowed?'تم تحميل سياسة التوجيه.':'email.routing معطلة في حزمة هذا النطاق.',featureAllowed?'ok':'error');
    }catch(err){featureAllowed=false;conflicts={mailboxes:0,forwarders:0,catchall_forward:false};updateControls();say(err.message,'error');}
  }
  async function bootstrap(){
    try{
      const data=await api('/api/mail');
      providerOnline=!!data.provider?.online;
      const domains=data.available_domains||[];
      domain.replaceChildren();
      if(!domains.length){const option=document.createElement('option');option.value='';option.textContent='لا توجد نطاقات ضمن نطاقك';domain.append(option);domain.disabled=true;featureAllowed=false;updateControls();say('لا توجد نطاقات متاحة.','error');return;}
      for(const item of domains){const option=document.createElement('option');option.value=item.domain;option.textContent=item.owner==='admin'?item.domain:`${item.domain} · ${item.owner}`;domain.append(option);}
      domain.disabled=false;
      await loadPolicy();
    }catch(err){providerOnline=false;featureAllowed=false;updateControls();say(`تعذر تحميل Email Routing: ${err.message}`,'error');}
  }
  domain.addEventListener('change',loadPolicy);
  mode.addEventListener('change',updateControls);
  shell.querySelector('#mailRoutingForm').addEventListener('submit',async event=>{
    event.preventDefault();
    if(!providerOnline)return say('Mail Provider غير متصل.','error');
    if(!featureAllowed)return say('email.routing معطلة في حزمة هذا النطاق.','error');
    if(mode.value==='remote'&&hasConflicts())return say('أزل Mailboxes وForwarders وCatch-all المحلي قبل Remote Mail Exchanger.','error');
    const payload={domain:domain.value,mode:mode.value};
    save.disabled=true;say('جاري تطبيق Email Routing عبر Mail Provider…');
    try{
      const result=await api('/api/mail/routing',{method:'PUT',body:JSON.stringify(payload)});
      mode.value=result.routing?.mode==='remote'?'remote':'local';
      await loadPolicy();
      say(mode.value==='remote'?'تم تحويل النطاق إلى Remote Mail Exchanger. تأكد أن DNS MX يشير إلى المزود الخارجي.':'تم تثبيت النطاق كـ Local Mail Exchanger.','ok');
    }catch(err){
      if(err.body?.local_resources)conflicts=err.body.local_resources;
      updateControls();
      say(err.status===428?'يلزم Step-Up Authentication قبل تعديل Email Routing.':err.message,'error');
    }
  });
  bootstrap();
})();
