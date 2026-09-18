(()=>{
  const root=document.getElementById('mail');
  if(!root)return;
  const csrf=document.querySelector('meta[name="csrf-token"]')?.content||'';
  const providerState=document.getElementById('mailProviderState');
  const providerEngine=document.getElementById('mailProviderEngine');
  const notice=document.getElementById('mailNotice');
  const mailboxUsage=document.getElementById('mailboxUsage');
  const forwarderUsage=document.getElementById('forwarderUsage');
  const mailboxDomain=document.getElementById('mailboxDomain');
  const forwarderDomain=document.getElementById('forwarderDomain');
  const passwordMailbox=document.getElementById('mailPasswordMailbox');
  const mailboxList=document.getElementById('mailboxList');
  const forwarderList=document.getElementById('forwarderList');
  const status=document.getElementById('mailStatus');
  let state={mailboxes:[],forwarders:[],available_domains:[],provider:{online:false,engine:'offline'},mailbox_limit:0,forwarder_limit:0};

  const importer=document.createElement('section');
  importer.className='panel mail-import-shell royal-frame';
  importer.innerHTML=`
    <div class="section-head">
      <div>
        <small>PROVIDER-GRADE BULK IMPORT</small>
        <h3>مستورد عناوين البريد</h3>
      </div>
      <span class="mail-chip">MAX 100</span>
    </div>
    <form id="mailImportForm" class="mail-form" autocomplete="off">
      <label>النطاق
        <select id="mailImportDomain" required></select>
      </label>
      <label class="full-row">الدفعة
        <textarea id="mailImportRows" rows="6" required spellcheck="false" autocapitalize="off" placeholder="mailbox,alice,StrongPassword!,1024&#10;forwarder,sales,sales@example.net"></textarea>
      </label>
      <div class="mail-policy-note">سطر Mailbox: <code>mailbox,localpart,password,quota_mb</code> · سطر Forwarder: <code>forwarder,localpart,destination</code>. المعالجة بحد أقصى 100 عنوان؛ كلمات المرور لا تُحفظ في المتصفح وتُمسح بعد نجاح العملية. الخادم يعيد تطبيق الصلاحيات وStep-Up والـQuota وفحص التعارضات قبل أي Provider write.</div>
      <button id="mailImportSubmit" type="submit" class="primary">استيراد الدفعة</button>
      <div id="mailImportStatus" class="mail-status" role="status" aria-live="polite"></div>
    </form>`;
  root.querySelector('.mail-inventory-grid')?.before(importer);
  const importForm=document.getElementById('mailImportForm');
  const importDomain=document.getElementById('mailImportDomain');
  const importRows=document.getElementById('mailImportRows');
  const importStatus=document.getElementById('mailImportStatus');

  const say=(msg,kind='')=>{status.textContent=msg||'';status.className=`mail-status ${kind}`.trim();};
  const sayImport=(msg,kind='')=>{if(!importStatus)return;importStatus.textContent=msg||'';importStatus.className=`mail-status ${kind}`.trim();};
  const api=async(url,opts={})=>{const headers={...(opts.headers||{})};if(opts.method&&opts.method!=='GET')headers['X-CSRF-Token']=csrf;if(opts.body&&!headers['Content-Type'])headers['Content-Type']='application/json';const r=await fetch(url,{credentials:'same-origin',...opts,headers});let body={};try{body=await r.json();}catch{}if(!r.ok)throw Object.assign(new Error(body.error||`HTTP ${r.status}`),{status:r.status,body});return body;};
  const empty=(text)=>{const d=document.createElement('div');d.className='empty-state';d.textContent=text;return d;};
  const deleteButton=(label,id,type)=>{const b=document.createElement('button');b.type='button';b.className='tiny danger';b.textContent=label;b.dataset.id=String(id);b.dataset.type=type;return b;};

  function fillDomains(select,feature){
    const current=select.value;select.replaceChildren();
    const rows=state.available_domains.filter(d=>d[feature]);
    if(!rows.length){const o=document.createElement('option');o.value='';o.textContent='لا توجد نطاقات متاحة بهذه الصلاحية';select.append(o);select.disabled=true;return;}
    select.disabled=false;
    for(const d of rows){const o=document.createElement('option');o.value=d.domain;o.textContent=d.owner==='admin'?d.domain:`${d.domain} · ${d.owner}`;select.append(o);}
    if(rows.some(d=>d.domain===current))select.value=current;
  }
  function fillImportDomains(){
    if(!importDomain)return;
    const current=importDomain.value;importDomain.replaceChildren();
    const rows=state.available_domains.filter(d=>d.email_accounts||d.email_forwarders);
    if(!rows.length){const o=document.createElement('option');o.value='';o.textContent='لا توجد نطاقات بريد ضمن نطاقك';importDomain.append(o);importDomain.disabled=true;return;}
    importDomain.disabled=false;
    for(const d of rows){const o=document.createElement('option');o.value=d.domain;o.textContent=d.owner==='admin'?d.domain:`${d.domain} · ${d.owner}`;importDomain.append(o);}
    if(rows.some(d=>d.domain===current))importDomain.value=current;
  }
  function fillPasswordMailboxes(){
    if(!passwordMailbox)return;
    const current=passwordMailbox.value;passwordMailbox.replaceChildren();
    const rows=state.mailboxes.filter(m=>m.enabled);
    if(!rows.length){const o=document.createElement('option');o.value='';o.textContent='لا توجد Mailboxes فعالة';passwordMailbox.append(o);passwordMailbox.disabled=true;return;}
    passwordMailbox.disabled=false;
    for(const m of rows){const o=document.createElement('option');o.value=String(m.id);o.textContent=`${m.localpart}@${m.domain}`;passwordMailbox.append(o);}
    if(rows.some(m=>String(m.id)===current))passwordMailbox.value=current;
  }

  function parseImportRows(raw){
    const lines=String(raw||'').split(/\r?\n/).map(line=>line.trim()).filter(Boolean);
    if(!lines.length)throw new Error('أدخل سطرًا واحدًا على الأقل للاستيراد.');
    if(lines.length>100)throw new Error('الحد الأقصى للاستيراد هو 100 عنوان في الدفعة.');
    return lines.map((line,index)=>{
      const fields=line.split(',').map(value=>value.trim());
      const kind=(fields[0]||'').toLowerCase();
      const localpart=fields[1]||'';
      if(kind==='mailbox'){
        if(fields.length!==4||!localpart||!fields[2])throw new Error(`تنسيق Mailbox غير صالح في السطر ${index+1}.`);
        const quota=Number(fields[3]);
        if(!Number.isInteger(quota))throw new Error(`Quota غير صالح في السطر ${index+1}.`);
        return {kind:'mailbox',localpart,password:fields[2],quota_mb:quota};
      }
      if(kind==='forwarder'){
        if(fields.length!==3||!localpart||!fields[2])throw new Error(`تنسيق Forwarder غير صالح في السطر ${index+1}.`);
        return {kind:'forwarder',localpart,destination:fields[2]};
      }
      throw new Error(`نوع غير معروف في السطر ${index+1}; استخدم mailbox أو forwarder.`);
    });
  }

  function renderProvider(){
    const online=!!state.provider?.online;root.classList.toggle('mail-provider-offline',!online);
    providerState.textContent=online?'ONLINE':'OFFLINE';providerState.style.color=online?'#48ffae':'#ff7d7d';
    providerEngine.textContent=state.provider?.engine||'offline';
    notice.className=`mail-notice royal-frame ${online?'online':'offline'}`;
    notice.textContent=online?'Mail Provider متصل. إنشاء البريد والتحويلات وتدوير كلمات المرور تنفذ فعليًا عبر Postfix/Dovecot Agent.':'Mail Provider غير متصل. البيانات مرئية، لكن عمليات البريد متوقفة حتى تثبيت الخادم بخيار --with-mail.';
  }

  function renderMailboxes(){
    mailboxList.replaceChildren();
    if(!state.mailboxes.length){mailboxList.append(empty('لا توجد صناديق بريد حتى الآن.'));return;}
    for(const m of state.mailboxes){const row=document.createElement('div');row.className='mail-row';
      const main=document.createElement('div');main.className='mail-row-main';const s=document.createElement('strong');s.textContent=`${m.localpart}@${m.domain}`;const span=document.createElement('span');span.textContent=`Owner: ${m.owner}`;main.append(s,span);
      const meta=document.createElement('div');meta.className='mail-row-meta';const b=document.createElement('b');b.textContent=m.enabled?'ACTIVE':'DISABLED';const sm=document.createElement('small');sm.textContent=`Quota ${m.quota_mb} MB`;meta.append(b,sm);
      row.append(main,meta,deleteButton('حذف',m.id,'mailbox'));mailboxList.append(row);}
  }
  function renderForwarders(){
    forwarderList.replaceChildren();
    if(!state.forwarders.length){forwarderList.append(empty('لا توجد تحويلات بريد حتى الآن.'));return;}
    for(const f of state.forwarders){const row=document.createElement('div');row.className='mail-row';
      const main=document.createElement('div');main.className='mail-row-main';const s=document.createElement('strong');s.textContent=`${f.localpart}@${f.domain}`;const span=document.createElement('span');span.textContent=`→ ${f.destination}`;main.append(s,span);
      const meta=document.createElement('div');meta.className='mail-row-meta';const b=document.createElement('b');b.textContent=f.enabled?'ACTIVE':'DISABLED';const sm=document.createElement('small');sm.textContent=`Owner: ${f.owner}`;meta.append(b,sm);
      row.append(main,meta,deleteButton('حذف',f.id,'forwarder'));forwarderList.append(row);}
  }
  function render(){
    renderProvider();fillDomains(mailboxDomain,'email_accounts');fillDomains(forwarderDomain,'email_forwarders');fillImportDomains();fillPasswordMailboxes();
    mailboxUsage.textContent=`${state.mailboxes.length} / ${state.mailbox_limit??0}`;forwarderUsage.textContent=`${state.forwarders.length} / ${state.forwarder_limit??0}`;
    renderMailboxes();renderForwarders();
  }
  async function load(){try{state=await api('/api/mail');render();}catch(e){say(e.message,'error');notice.textContent='تعذر قراءة حالة Email Center.';notice.className='mail-notice royal-frame offline';}}

  document.getElementById('mailRefresh')?.addEventListener('click',load);
  document.getElementById('mailboxForm')?.addEventListener('submit',async(e)=>{e.preventDefault();if(!state.provider?.online)return say('Mail Provider غير متصل.','error');say('جاري إنشاء Mailbox…');try{await api('/api/mail/mailboxes',{method:'POST',body:JSON.stringify({domain:mailboxDomain.value,localpart:document.getElementById('mailboxLocalpart').value.trim(),password:document.getElementById('mailboxPassword').value,quota_mb:Number(document.getElementById('mailboxQuota').value)})});e.currentTarget.reset();document.getElementById('mailboxQuota').value='1024';say('تم إنشاء Mailbox وربطه بـPostfix/Dovecot.','ok');await load();}catch(err){say(err.status===428?'يلزم Step-Up Authentication من صفحة الأمن أولًا.':err.message,'error');}});
  document.getElementById('forwarderForm')?.addEventListener('submit',async(e)=>{e.preventDefault();if(!state.provider?.online)return say('Mail Provider غير متصل.','error');say('جاري إنشاء Forwarder…');try{await api('/api/mail/forwarders',{method:'POST',body:JSON.stringify({domain:forwarderDomain.value,localpart:document.getElementById('forwarderLocalpart').value.trim(),destination:document.getElementById('forwarderDestination').value.trim()})});e.currentTarget.reset();say('تم إنشاء Forwarder.','ok');await load();}catch(err){say(err.status===428?'يلزم Step-Up Authentication من صفحة الأمن أولًا.':err.message,'error');}});
  document.getElementById('mailPasswordForm')?.addEventListener('submit',async(e)=>{e.preventDefault();if(!state.provider?.online)return say('Mail Provider غير متصل.','error');const id=Number(passwordMailbox?.value||0);const password=document.getElementById('mailPasswordNew')?.value||'';const confirm=document.getElementById('mailPasswordConfirm')?.value||'';if(!id)return say('اختر Mailbox فعالة أولًا.','error');if(password!==confirm)return say('تأكيد كلمة المرور غير مطابق.','error');say('جاري تدوير كلمة مرور Mailbox…');try{await api(`/api/mail/mailboxes/${id}/password`,{method:'PUT',body:JSON.stringify({password})});document.getElementById('mailPasswordNew').value='';document.getElementById('mailPasswordConfirm').value='';say('تم تغيير كلمة مرور Mailbox وتفعيل Hash الجديد بعد نجاح Validation/Reload.','ok');await load();}catch(err){say(err.status===428?'يلزم Step-Up Authentication من صفحة الأمن أولًا.':err.message,'error');}});
  importForm?.addEventListener('submit',async(e)=>{
    e.preventDefault();
    if(!state.provider?.online)return sayImport('Mail Provider غير متصل.','error');
    try{
      const entries=parseImportRows(importRows?.value||'');
      sayImport(`جاري التحقق واستيراد ${entries.length} عنوان…`);
      const result=await api('/api/mail/import',{method:'POST',body:JSON.stringify({domain:importDomain?.value||'',entries})});
      if(importRows)importRows.value='';
      sayImport(`تم استيراد ${result.imported} عنوان: ${result.mailboxes} Mailbox و${result.forwarders} Forwarder.`,'ok');
      await load();
    }catch(err){sayImport(err.status===428?'يلزم Step-Up Authentication من صفحة الأمن أولًا.':err.message,'error');}
  });
  root.addEventListener('click',async(e)=>{const b=e.target.closest('button[data-type][data-id]');if(!b)return;if(!state.provider?.online)return say('Mail Provider غير متصل.','error');const id=Number(b.dataset.id);const endpoint=b.dataset.type==='mailbox'?`/api/mail/mailboxes/${id}`:`/api/mail/forwarders/${id}`;b.disabled=true;try{await api(endpoint,{method:'DELETE'});say(b.dataset.type==='mailbox'?'تم حذف Mailbox ونقل بياناته إلى quarantine.':'تم حذف Forwarder.','ok');await load();}catch(err){say(err.message,'error');b.disabled=false;}});
  load();
})();
