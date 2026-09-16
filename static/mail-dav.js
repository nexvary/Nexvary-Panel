(()=>{
  const root=document.getElementById('mail');if(!root||root.querySelector('#mailDavShell'))return;
  const anchor=root.querySelector('.mail-trace-shell');if(!anchor)return;
  const csrf=document.querySelector('meta[name="csrf-token"]')?.content||'';
  const shell=document.createElement('article');
  shell.id='mailDavShell';
  shell.className='panel royal-frame frame-silver mail-dav-shell';
  shell.innerHTML=`
    <div class="panel-head">
      <div><span class="kicker">CALDAV · CARDDAV · RADICALE</span><h3>التقويم وجهات الاتصال</h3></div>
      <span id="mailDavState" class="mail-chip">CHECKING</span>
    </div>
    <div class="mail-policy-note">حساب DAV مستقل مرتبط بصندوق البريد. كلمة مرور DAV لا تُحفظ في SQLite أو Audit؛ تُحوّل مباشرة إلى bcrypt داخل Provider. استخدم نفس نقطة الاتصال في تطبيقات التقويم وجهات الاتصال.</div>
    <div class="mail-dav-endpoint"><small>DAV ENDPOINT</small><strong id="mailDavEndpoint">—</strong></div>
    <form id="mailDavForm" class="mail-form automation-form" autocomplete="off">
      <input id="mailDavAccountId" type="hidden" value="0">
      <label>Mailbox<select id="mailDavMailbox" required><option value="">جاري تحميل Mailboxes…</option></select></label>
      <label>كلمة مرور DAV<input id="mailDavPassword" type="password" minlength="14" maxlength="128" autocomplete="new-password" required></label>
      <div class="mail-policy-note full-row">استخدم كلمة مرور مختلفة عن كلمة مرور البريد. التعديل والحذف يتطلبان Step-Up Authentication.</div>
      <div class="mail-row-actions full-row">
        <button id="mailDavSave" class="primary royal-action" type="submit">تفعيل Calendars & Contacts</button>
        <button id="mailDavCancel" class="tiny ghost" type="button" hidden>إلغاء التدوير</button>
      </div>
      <div id="mailDavStatus" class="mail-status full-row" role="status" aria-live="polite"></div>
    </form>
    <div class="panel-head"><div><span class="kicker">PROVISIONED DAV IDENTITIES</span><h3>الحسابات المفعلة</h3></div><span id="mailDavCount" class="mail-chip">0</span></div>
    <div id="mailDavList" class="mail-list"><div class="empty-state">جاري التحميل…</div></div>`;
  anchor.before(shell);

  const $=s=>shell.querySelector(s);
  const mailbox=$('#mailDavMailbox'),password=$('#mailDavPassword'),accountId=$('#mailDavAccountId');
  const save=$('#mailDavSave'),cancel=$('#mailDavCancel'),state=$('#mailDavState'),status=$('#mailDavStatus');
  const endpoint=$('#mailDavEndpoint'),count=$('#mailDavCount'),list=$('#mailDavList');
  let providerOnline=false,mailboxes=[],accounts=[];
  const say=(msg,kind='')=>{status.textContent=msg||'';status.className=`mail-status full-row ${kind}`.trim();};
  const api=async(url,opt={})=>{const headers={Accept:'application/json',...(opt.headers||{})};if(opt.method&&opt.method!=='GET')headers['X-CSRF-Token']=csrf;if(opt.body&&!headers['Content-Type'])headers['Content-Type']='application/json';const r=await fetch(url,{credentials:'same-origin',...opt,headers});let b={};try{b=await r.json()}catch{}if(!r.ok)throw Object.assign(new Error(b.error||`HTTP ${r.status}`),{status:r.status,body:b});return b;};
  const stepMessage=e=>e.status===428?'يلزم Step-Up Authentication قبل تعديل Calendars & Contacts.':e.message;

  function reset(){accountId.value='0';mailbox.disabled=false;password.value='';save.textContent='تفعيل Calendars & Contacts';cancel.hidden=true;updateControls();}
  function updateControls(){const selected=mailboxes.find(item=>String(item.id)===mailbox.value);const allowed=!!selected?.feature_allowed;const locked=!providerOnline||!selected||!allowed;password.disabled=locked;save.disabled=locked;state.textContent=!providerOnline?'PROVIDER OFFLINE':'RADICALE · ACTIVE';if(selected&&!allowed)say('email.calendars_contacts معطلة في حزمة هذا الحساب.','error');}
  function renderMailboxOptions(){const current=mailbox.value;mailbox.replaceChildren();const provisioned=new Set(accounts.map(item=>Number(item.mailbox_id)));const available=mailboxes.filter(item=>!provisioned.has(Number(item.id))||String(item.id)===current);if(!available.length){const o=document.createElement('option');o.value='';o.textContent='لا توجد Mailboxes غير مفعلة';mailbox.append(o);return;}for(const item of available){const o=document.createElement('option');o.value=String(item.id);o.textContent=item.owner==='admin'?item.address:`${item.address} · ${item.owner}`;mailbox.append(o);}if(current&&available.some(item=>String(item.id)===current))mailbox.value=current;}
  function renderAccounts(){list.replaceChildren();count.textContent=String(accounts.length);if(!accounts.length){const empty=document.createElement('div');empty.className='empty-state';empty.textContent='لا توجد حسابات CalDAV/CardDAV مفعلة.';list.append(empty);return;}for(const item of accounts){const row=document.createElement('div');row.className='mail-row';const main=document.createElement('div');main.className='mail-row-main';const title=document.createElement('strong');title.textContent=item.username;const sub=document.createElement('span');sub.textContent=`${item.owner} · CalDAV + CardDAV · ${item.enabled?'ACTIVE':'DISABLED'}`;main.append(title,sub);const actions=document.createElement('div');actions.className='mail-row-actions';const rotate=document.createElement('button');rotate.type='button';rotate.className='tiny ghost';rotate.textContent='تدوير كلمة المرور';rotate.dataset.davRotate=String(item.id);const del=document.createElement('button');del.type='button';del.className='tiny danger';del.textContent='إلغاء DAV';del.dataset.davDelete=String(item.id);actions.append(rotate,del);row.append(main,actions);list.append(row);}}
  async function load(){say('جاري فحص DAV Provider…');try{const data=await api('/api/mail/dav');providerOnline=!!data.provider?.online;mailboxes=data.mailboxes||[];accounts=data.accounts||[];endpoint.textContent=`${window.location.origin}${data.endpoint||'/dav/'}`;renderMailboxOptions();renderAccounts();updateControls();say(providerOnline?'Radicale Provider متصل وجاهز.':'Radicale Provider غير متصل.','ok');if(!providerOnline)say('Radicale Provider غير متصل.','error');}catch(err){providerOnline=false;mailboxes=[];accounts=[];renderMailboxOptions();renderAccounts();updateControls();say(`تعذر تحميل Calendars & Contacts: ${err.message}`,'error');}}

  mailbox.addEventListener('change',()=>{say('');updateControls();});cancel.addEventListener('click',reset);
  $('#mailDavForm').addEventListener('submit',async event=>{event.preventDefault();const mailboxId=Number(mailbox.value||0);const id=Number(accountId.value||0);if(!mailboxId||password.value.length<14)return say('اختر Mailbox وأدخل كلمة مرور DAV من 14 حرفًا على الأقل.','error');save.disabled=true;say(id?'جاري تدوير كلمة مرور DAV…':'جاري تفعيل CalDAV/CardDAV…');try{const result=await api(id?`/api/mail/dav/accounts/${id}`:'/api/mail/dav/accounts',{method:id?'PUT':'POST',body:JSON.stringify(id?{password:password.value}:{mailbox_id:mailboxId,password:password.value})});password.value='';if(id){accounts=accounts.map(item=>Number(item.id)===id?result.account:item);}else{accounts=[...accounts,result.account];}reset();renderMailboxOptions();renderAccounts();say(id?'تم تدوير كلمة مرور DAV بنجاح.':'تم تفعيل Calendars & Contacts للحساب.','ok');}catch(err){password.value='';say(stepMessage(err),'error');}finally{updateControls();}});
  list.addEventListener('click',async event=>{const rotate=event.target.closest('[data-dav-rotate]');if(rotate){const item=accounts.find(row=>String(row.id)===rotate.dataset.davRotate);if(!item)return;accountId.value=String(item.id);renderMailboxOptions();mailbox.value=String(item.mailbox_id);mailbox.disabled=true;password.value='';save.textContent='حفظ كلمة مرور DAV الجديدة';cancel.hidden=false;updateControls();password.focus();say(`تدوير Credential لـ ${item.username}`);return;}const del=event.target.closest('[data-dav-delete]');if(!del)return;del.disabled=true;say('جاري إلغاء DAV Credential…');try{const id=Number(del.dataset.davDelete);await api(`/api/mail/dav/accounts/${id}`,{method:'DELETE'});accounts=accounts.filter(item=>Number(item.id)!==id);reset();renderMailboxOptions();renderAccounts();say('تم إلغاء CalDAV/CardDAV Credential.','ok');}catch(err){del.disabled=false;say(stepMessage(err),'error');}});
  load();
})();
