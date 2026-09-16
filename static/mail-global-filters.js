(()=>{
  const root=document.getElementById('mail');if(!root||root.querySelector('#mailGlobalFilterShell'))return;
  const csrf=document.querySelector('meta[name="csrf-token"]')?.content||'';
  const anchor=root.querySelector('.mail-automation-shell');if(!anchor)return;
  const shell=document.createElement('article');
  shell.id='mailGlobalFilterShell';
  shell.className='panel royal-frame frame-electric-black mail-global-filter-shell';
  shell.innerHTML=`
    <div class="panel-head">
      <div><span class="kicker">GLOBAL EMAIL FILTERS · ACCOUNT SCOPE</span><h3>فلاتر البريد العامة</h3></div>
      <span id="mailGlobalFilterState" class="mail-chip">POLICY CHECK</span>
    </div>
    <div class="mail-policy-note">تُطبق هذه القواعد على كل Mailbox داخل حساب الاستضافة المحدد، عبر Dovecot Sieve. يتم منع Redirect إلى أي نطاق داخل الحساب نفسه لتفادي حلقات البريد، وكل تعديل يتطلب Step-Up ويُعاد مزامنته مع صناديق الحساب مع Rollback عند فشل المزود.</div>
    <form id="mailGlobalFilterForm" class="mail-form automation-form" autocomplete="off">
      <input id="mailGlobalFilterId" type="hidden" value="0">
      <label>نطاق لتحديد الحساب<select id="mailGlobalFilterDomain" required><option value="">جاري تحميل النطاقات…</option></select></label>
      <label>الحقل<select id="mailGlobalFilterField"><option value="subject">Subject</option><option value="from">From</option><option value="to">To</option><option value="header">Custom Header</option></select></label>
      <label id="mailGlobalHeaderWrap" class="full-row" hidden>اسم Header<input id="mailGlobalFilterHeader" maxlength="63" placeholder="X-Campaign-ID"></label>
      <label>المطابقة<select id="mailGlobalFilterMatch"><option value="contains">Contains</option><option value="is">Is exactly</option></select></label>
      <label>الأولوية<input id="mailGlobalFilterPriority" type="number" min="1" max="10000" value="100"></label>
      <label class="full-row">القيمة<input id="mailGlobalFilterPattern" maxlength="200" required placeholder="invoice"></label>
      <label>الإجراء<select id="mailGlobalFilterAction"><option value="fileinto">Move to folder</option><option value="redirect">Redirect</option><option value="discard">Discard</option></select></label>
      <label>الوجهة<input id="mailGlobalFilterDestination" maxlength="320" placeholder="Global أو archive@external.example"></label>
      <label class="mail-toggle"><input id="mailGlobalFilterEnabled" type="checkbox" checked><span>تفعيل القاعدة</span></label>
      <div class="mail-row-actions full-row">
        <button id="mailGlobalFilterSave" class="primary royal-action" type="submit">إضافة Global Filter</button>
        <button id="mailGlobalFilterCancel" class="tiny ghost" type="button" hidden>إلغاء التعديل</button>
      </div>
      <div id="mailGlobalFilterStatus" class="mail-status full-row" role="status" aria-live="polite"></div>
    </form>
    <div class="panel-head"><div><span class="kicker">ACCOUNT-WIDE INVENTORY</span><h3>القواعد النشطة</h3></div><span id="mailGlobalFilterScope" class="mail-chip">—</span></div>
    <div id="mailGlobalFilterList" class="mail-list automation-list"><div class="empty-state">اختر نطاقًا لتحميل فلاتر الحساب.</div></div>`;
  anchor.before(shell);

  const $=s=>shell.querySelector(s);
  const domain=$('#mailGlobalFilterDomain'),field=$('#mailGlobalFilterField'),headerWrap=$('#mailGlobalHeaderWrap'),header=$('#mailGlobalFilterHeader');
  const match=$('#mailGlobalFilterMatch'),priority=$('#mailGlobalFilterPriority'),pattern=$('#mailGlobalFilterPattern');
  const action=$('#mailGlobalFilterAction'),destination=$('#mailGlobalFilterDestination'),enabled=$('#mailGlobalFilterEnabled');
  const idField=$('#mailGlobalFilterId'),save=$('#mailGlobalFilterSave'),cancel=$('#mailGlobalFilterCancel');
  const state=$('#mailGlobalFilterState'),scope=$('#mailGlobalFilterScope'),status=$('#mailGlobalFilterStatus'),inventory=$('#mailGlobalFilterList');
  let providerOnline=false,featureAllowed=false,rows=[],ownerDomains=[],owner='',mailboxCount=0;

  const say=(msg,kind='')=>{status.textContent=msg||'';status.className=`mail-status full-row ${kind}`.trim();};
  const api=async(url,opt={})=>{const headers={Accept:'application/json',...(opt.headers||{})};if(opt.method&&opt.method!=='GET')headers['X-CSRF-Token']=csrf;if(opt.body&&!headers['Content-Type'])headers['Content-Type']='application/json';const r=await fetch(url,{credentials:'same-origin',...opt,headers});let b={};try{b=await r.json()}catch{}if(!r.ok)throw Object.assign(new Error(b.error||`HTTP ${r.status}`),{status:r.status,body:b});return b;};
  const safeStepError=e=>e.status===428?'يلزم Step-Up Authentication قبل تعديل Global Email Filters.':e.message;

  function fieldChanged(){const custom=field.value==='header';headerWrap.hidden=!custom;header.required=custom;header.disabled=!custom||!providerOnline||!featureAllowed||!domain.value;if(!custom)header.value='';}
  function actionChanged(){const a=action.value;if(a==='discard'){destination.value='';destination.disabled=true;destination.required=false;destination.placeholder='لا توجد وجهة';}else{destination.disabled=!providerOnline||!featureAllowed||!domain.value;destination.required=true;destination.placeholder=a==='fileinto'?'Global':'archive@external.example';}}
  function updateControls(){const locked=!providerOnline||!featureAllowed||!domain.value;for(const el of [field,match,priority,pattern,action,enabled,save])el.disabled=locked;fieldChanged();actionChanged();if(locked){header.disabled=true;destination.disabled=true;}state.textContent=!providerOnline?'PROVIDER OFFLINE':featureAllowed?'FOUNDATION · ACTIVE':'DISABLED BY PACKAGE';scope.textContent=owner?`${owner} · ${mailboxCount} MAILBOX`:'—';}
  function resetForm(){idField.value='0';field.value='subject';header.value='';match.value='contains';priority.value='100';pattern.value='';action.value='fileinto';destination.value='';enabled.checked=true;domain.disabled=false;save.textContent='إضافة Global Filter';cancel.hidden=true;fieldChanged();actionChanged();updateControls();}
  function describe(item){const headerName=item.field==='header'?(item.header_name||'Header'):item.field;return `${headerName} ${item.match_type} “${item.pattern}”`;}
  function render(){inventory.replaceChildren();if(!rows.length){const empty=document.createElement('div');empty.className='empty-state';empty.textContent='لا توجد Global Filters لهذا الحساب.';inventory.append(empty);return;}for(const item of rows){const row=document.createElement('div');row.className='mail-row automation-row';const main=document.createElement('div');main.className='mail-row-main';const title=document.createElement('strong');title.textContent=describe(item);const sub=document.createElement('span');sub.textContent=`${item.action}${item.destination?` → ${item.destination}`:''} · priority ${item.priority} · ${item.enabled?'ACTIVE':'DISABLED'}`;main.append(title,sub);const actions=document.createElement('div');actions.className='mail-row-actions';const edit=document.createElement('button');edit.type='button';edit.className='tiny ghost';edit.textContent='تعديل';edit.dataset.globalFilterEdit=String(item.id);const del=document.createElement('button');del.type='button';del.className='tiny danger';del.textContent='حذف';del.dataset.globalFilterDelete=String(item.id);actions.append(edit,del);row.append(main,actions);inventory.append(row);}}
  function payload(){return {domain:domain.value,field:field.value,header_name:header.value.trim(),match_type:match.value,priority:Number(priority.value),pattern:pattern.value.trim(),action:action.value,destination:action.value==='discard'?'':destination.value.trim(),enabled:enabled.checked};}
  function validateClient(data){if(data.field==='header'&&!/^[A-Za-z0-9][A-Za-z0-9-]{0,62}$/.test(data.header_name))return 'اسم Header غير صالح.';if(data.action==='redirect'){const parts=data.destination.toLowerCase().split('@');if(parts.length!==2)return 'وجهة Redirect غير صالحة.';if(ownerDomains.includes(parts[1].replace(/\.$/,'')))return 'لا يمكن Redirect إلى نطاق داخل حساب الاستضافة نفسه.';}return '';}
  function acknowledgedRows(result,id,data){const serverRows=Array.isArray(result?.filters)?result.filters:[];if(!id)return serverRows;const source=serverRows.length?serverRows:rows;return source.map(item=>Number(item.id)===id?{...item,...data,enabled:data.enabled?1:0}:item);}

  async function loadScope(){if(!domain.value){featureAllowed=false;rows=[];owner='';mailboxCount=0;render();updateControls();return;}say('جاري تحميل Global Email Filters…');try{const data=await api(`/api/mail/global-filters?domain=${encodeURIComponent(domain.value)}`);featureAllowed=!!data.feature_allowed;rows=data.filters||[];ownerDomains=data.owner_domains||[];owner=data.owner||'';mailboxCount=Number(data.mailbox_count||0);render();updateControls();say(featureAllowed?'تم تحميل فلاتر الحساب.':'الميزة معطلة في حزمة هذا الحساب.',featureAllowed?'ok':'error');}catch(err){featureAllowed=false;rows=[];owner='';mailboxCount=0;render();updateControls();say(err.message,'error');}}
  async function bootstrap(){try{const data=await api('/api/mail');providerOnline=!!data.provider?.online;const domains=data.available_domains||[];domain.replaceChildren();if(!domains.length){const o=document.createElement('option');o.value='';o.textContent='لا توجد نطاقات بريد ضمن نطاقك';domain.append(o);domain.disabled=true;featureAllowed=false;updateControls();say('لا توجد نطاقات متاحة.','error');return;}for(const item of domains){const o=document.createElement('option');o.value=item.domain;o.textContent=item.owner==='admin'?item.domain:`${item.domain} · ${item.owner}`;domain.append(o);}domain.disabled=false;await loadScope();}catch(err){providerOnline=false;featureAllowed=false;updateControls();say(`تعذر تهيئة Global Email Filters: ${err.message}`,'error');}}

  field.addEventListener('change',fieldChanged);action.addEventListener('change',actionChanged);domain.addEventListener('change',()=>{resetForm();loadScope();});cancel.addEventListener('click',resetForm);
  $('#mailGlobalFilterForm').addEventListener('submit',async event=>{event.preventDefault();if(!providerOnline)return say('Mail Provider غير متصل.','error');if(!featureAllowed)return say('email.global_filters معطلة في حزمة الحساب.','error');const data=payload();const validation=validateClient(data);if(validation)return say(validation,'error');const id=Number(idField.value||0);save.disabled=true;say(id?'جاري تحديث Global Filter ومزامنة Mailboxes…':'جاري إنشاء Global Filter ومزامنة Mailboxes…');try{const result=await api(id?`/api/mail/global-filters/${id}`:'/api/mail/global-filters',{method:id?'PUT':'POST',body:JSON.stringify(data)});rows=acknowledgedRows(result,id,data);mailboxCount=Number(result.mailbox_count||mailboxCount);render();resetForm();say(id?'تم تحديث Global Filter ومزامنة الحساب بنجاح.':'تم إنشاء Global Filter وتطبيقه على الحساب.','ok');}catch(err){say(safeStepError(err),'error');}finally{updateControls();}});
  inventory.addEventListener('click',async event=>{const edit=event.target.closest('[data-global-filter-edit]');if(edit){const item=rows.find(row=>String(row.id)===edit.dataset.globalFilterEdit);if(!item)return;idField.value=String(item.id);domain.disabled=true;field.value=item.field;header.value=item.header_name||'';match.value=item.match_type;priority.value=String(item.priority);pattern.value=item.pattern;action.value=item.action;destination.value=item.destination||'';enabled.checked=!!item.enabled;save.textContent='حفظ Global Filter';cancel.hidden=false;fieldChanged();actionChanged();say(`تعديل Global Filter #${item.id}`);return;}const del=event.target.closest('[data-global-filter-delete]');if(!del)return;del.disabled=true;say('جاري حذف Global Filter وإعادة مزامنة Mailboxes…');try{const result=await api(`/api/mail/global-filters/${del.dataset.globalFilterDelete}`,{method:'DELETE'});rows=result.filters||[];mailboxCount=Number(result.mailbox_count||mailboxCount);render();resetForm();say('تم حذف Global Filter واستعادة Sieve بشكل متسق.','ok');}catch(err){del.disabled=false;say(safeStepError(err),'error');}});
  fieldChanged();actionChanged();bootstrap();
})();
