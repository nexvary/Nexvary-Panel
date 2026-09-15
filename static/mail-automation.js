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
