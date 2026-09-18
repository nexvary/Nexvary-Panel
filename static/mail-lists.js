(()=>{
  const root=document.getElementById('mail');
  if(!root||root.querySelector('#mailingListShell'))return;
  const csrf=document.querySelector('meta[name="csrf-token"]')?.content||'';
  const anchor=root.querySelector('.mail-trace-shell');
  if(!anchor)return;

  const shell=document.createElement('article');
  shell.id='mailingListShell';
  shell.className='panel royal-frame frame-silver mail-list-shell';
  shell.innerHTML=`
    <div class="panel-head">
      <div><span class="kicker">MAILING LISTS · PROVIDER DISTRIBUTION</span><h3>قوائم التوزيع البريدية</h3></div>
      <span id="mailingListState" class="mail-chip">PROVIDER POLICY</span>
    </div>
    <div class="mail-policy-note">هذه Foundation آمنة لقوائم توزيع يديرها مالك النطاق: عنوان واحد يوزّع إلى أعضاء محددين عبر Postfix. ليست Mailman ولا توفر اشتراكًا عامًا أو واجهة أرشيف. التعديل يتطلب Step-Up ويمنع الحلقات والتعارض مع Mailbox/Forwarder.</div>
    <div class="mail-create-grid mailing-list-grid">
      <form id="mailingListForm" class="mail-form automation-form" autocomplete="off">
        <input id="mailingListId" type="hidden" value="">
        <label>النطاق<select id="mailingListDomain" required><option value="">جاري تحميل النطاقات…</option></select></label>
        <label>اسم القائمة<input id="mailingListLocalpart" maxlength="64" required placeholder="team"></label>
        <label class="full-row">الأعضاء · بريد واحد في كل سطر<textarea id="mailingListMembers" rows="7" maxlength="24000" required placeholder="alice@example.net\nbob@example.net"></textarea></label>
        <div class="mail-policy-note full-row">الحد الأقصى 100 عضو. عند التعديل يستخدم Provider حالة متوقعة لمنع الكتابة فوق تغيير خارجي غير متوقع.</div>
        <div class="mail-list-actions full-row">
          <button id="mailingListSave" class="primary royal-action" type="submit">إنشاء Mailing List</button>
          <button id="mailingListCancel" class="tiny ghost" type="button" hidden>إلغاء التعديل</button>
        </div>
      </form>
      <div>
        <div class="panel-head"><div><span class="kicker">DISTRIBUTION INVENTORY</span><h3>القوائم الحالية</h3></div><button id="mailingListRefresh" class="tiny ghost" type="button">تحديث</button></div>
        <div id="mailingListInventory" class="mail-list"><div class="empty-state">جاري التحميل…</div></div>
      </div>
    </div>
    <div id="mailingListStatus" class="mail-status" role="status" aria-live="polite"></div>`;
  anchor.before(shell);

  const $=s=>shell.querySelector(s);
  const domain=$('#mailingListDomain');
  const localpart=$('#mailingListLocalpart');
  const members=$('#mailingListMembers');
  const idField=$('#mailingListId');
  const save=$('#mailingListSave');
  const cancel=$('#mailingListCancel');
  const inventory=$('#mailingListInventory');
  const state=$('#mailingListState');
  const status=$('#mailingListStatus');
  let providerOnline=false;
  let rows=[];

  const say=(msg,kind='')=>{status.textContent=msg||'';status.className=`mail-status ${kind}`.trim();};
  const api=async(url,opt={})=>{
    const headers={Accept:'application/json',...(opt.headers||{})};
    if(opt.method&&opt.method!=='GET')headers['X-CSRF-Token']=csrf;
    if(opt.body&&!headers['Content-Type'])headers['Content-Type']='application/json';
    const response=await fetch(url,{credentials:'same-origin',...opt,headers});
    let body={};try{body=await response.json()}catch{}
    if(!response.ok)throw Object.assign(new Error(body.error||`HTTP ${response.status}`),{status:response.status,body});
    return body;
  };
  const empty=text=>{const el=document.createElement('div');el.className='empty-state';el.textContent=text;return el;};
  const memberLines=()=>members.value.split(/\r?\n/).map(v=>v.trim().toLowerCase()).filter(Boolean);

  function resetForm(){
    idField.value='';
    localpart.disabled=false;
    domain.disabled=false;
    localpart.value='';
    members.value='';
    save.textContent='إنشاء Mailing List';
    cancel.hidden=true;
  }

  function render(){
    inventory.replaceChildren();
    if(!rows.length){inventory.append(empty('لا توجد قوائم توزيع بعد.'));return;}
    for(const item of rows){
      const row=document.createElement('div');row.className='mail-row mailing-list-row';
      const main=document.createElement('div');main.className='mail-row-main';
      const title=document.createElement('strong');title.textContent=item.address;
      const subtitle=document.createElement('span');subtitle.textContent=`${item.members.length} عضو · ${item.enabled?'ACTIVE':'DISABLED'}`;
      main.append(title,subtitle);
      const actions=document.createElement('div');actions.className='mail-row-actions';
      const edit=document.createElement('button');edit.type='button';edit.className='tiny ghost';edit.textContent='تعديل';edit.dataset.listEdit=String(item.id);
      const del=document.createElement('button');del.type='button';del.className='tiny danger';del.textContent='حذف';del.dataset.listDelete=String(item.id);
      actions.append(edit,del);row.append(main,actions);inventory.append(row);
    }
  }

  async function loadInventory(){
    try{
      const data=await api('/api/mail/mailing-lists');
      rows=data.mailing_lists||[];render();
      state.textContent=providerOnline?'FOUNDATION · ACTIVE':'PROVIDER OFFLINE';
    }catch(err){rows=[];render();state.textContent='UNAVAILABLE';say(`تعذر تحميل Mailing Lists: ${err.message}`,'error');}
  }

  async function bootstrap(){
    try{
      const data=await api('/api/mail');
      providerOnline=!!data.provider?.online;
      domain.replaceChildren();
      const domains=data.available_domains||[];
      if(!domains.length){const option=document.createElement('option');option.value='';option.textContent='لا توجد نطاقات ضمن نطاقك';domain.append(option);domain.disabled=true;save.disabled=true;state.textContent='NO DOMAINS';}
      else{
        for(const item of domains){const option=document.createElement('option');option.value=item.domain;option.textContent=item.owner==='admin'?item.domain:`${item.domain} · ${item.owner}`;domain.append(option);}
        domain.disabled=false;save.disabled=!providerOnline;state.textContent=providerOnline?'FOUNDATION · ACTIVE':'PROVIDER OFFLINE';
      }
      await loadInventory();
    }catch(err){providerOnline=false;save.disabled=true;state.textContent='PROVIDER OFFLINE';say(`تعذر تهيئة Mailing Lists: ${err.message}`,'error');}
  }

  shell.querySelector('#mailingListForm').addEventListener('submit',async event=>{
    event.preventDefault();
    if(!providerOnline)return say('Mail Provider غير متصل.','error');
    const parsed=memberLines();
    if(parsed.length<1||parsed.length>100)return say('أدخل من عضو واحد إلى 100 عضو، بريد واحد في كل سطر.','error');
    const listId=Number(idField.value||0);
    const payload=listId?{members:parsed}:{domain:domain.value,localpart:localpart.value.trim().toLowerCase(),members:parsed};
    save.disabled=true;say(listId?'جاري تحديث القائمة عبر Mail Provider…':'جاري إنشاء القائمة عبر Mail Provider…');
    try{
      const data=await api(listId?`/api/mail/mailing-lists/${listId}`:'/api/mail/mailing-lists',{method:listId?'PUT':'POST',body:JSON.stringify(payload)});
      resetForm();await loadInventory();
      say(listId?'تم تحديث Mailing List وإعادة تحميل Postfix بنجاح.':'تم إنشاء Mailing List وربطها بمزود البريد.','ok');
      if(data.mailing_list?.domain)domain.value=data.mailing_list.domain;
    }catch(err){say(err.status===428?'يلزم Step-Up Authentication قبل تعديل Mailing Lists.':err.message,'error');}
    finally{save.disabled=!providerOnline;}
  });

  inventory.addEventListener('click',async event=>{
    const edit=event.target.closest('[data-list-edit]');
    if(edit){
      const item=rows.find(row=>String(row.id)===edit.dataset.listEdit);if(!item)return;
      idField.value=String(item.id);domain.value=item.domain;domain.disabled=true;localpart.value=item.localpart;localpart.disabled=true;members.value=(item.members||[]).join('\n');save.textContent='حفظ أعضاء القائمة';cancel.hidden=false;say(`تعديل ${item.address}`);return;
    }
    const del=event.target.closest('[data-list-delete]');
    if(!del)return;
    del.disabled=true;say('جاري حذف Mailing List عبر Provider…');
    try{await api(`/api/mail/mailing-lists/${del.dataset.listDelete}`,{method:'DELETE'});resetForm();await loadInventory();say('تم حذف Mailing List واستعادة خريطة Postfix بشكل متسق.','ok');}
    catch(err){del.disabled=false;say(err.status===428?'يلزم Step-Up Authentication قبل حذف Mailing List.':err.message,'error');}
  });

  cancel.addEventListener('click',resetForm);
  shell.querySelector('#mailingListRefresh').addEventListener('click',()=>loadInventory());
  bootstrap();
})();
