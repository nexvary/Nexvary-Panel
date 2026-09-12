(()=>{
  const root=document.getElementById('schedules');
  if(!root) return;
  const csrf=document.querySelector('meta[name="csrf-token"]')?.content||'';
  const list=document.getElementById('scheduleList');
  const quota=document.getElementById('scheduleQuota');
  const status=document.getElementById('scheduleStatus');
  const form=document.getElementById('scheduleForm');
  const domain=document.getElementById('scheduleDomain');
  const taskType=document.getElementById('scheduleTaskType');
  const cadence=document.getElementById('scheduleCadence');
  const hour=document.getElementById('scheduleHour');
  const minute=document.getElementById('scheduleMinute');
  const weekday=document.getElementById('scheduleWeekday');
  let tasks=[];

  const say=(msg,kind='')=>{status.textContent=msg||'';status.className=`schedule-status ${kind}`.trim();};
  const api=async(url,opts={})=>{
    const headers={...(opts.headers||{})};
    if(opts.method&&opts.method!=='GET') headers['X-CSRF-Token']=csrf;
    if(opts.body&&!headers['Content-Type']) headers['Content-Type']='application/json';
    const r=await fetch(url,{credentials:'same-origin',...opts,headers});
    let body={};try{body=await r.json();}catch{}
    if(!r.ok) throw new Error(body.error||`HTTP ${r.status}`);
    return body;
  };
  const when=(ts)=>ts?new Date(ts*1000).toLocaleString('ar-EG',{timeZone:'UTC'})+' UTC':'لم يُنفذ بعد';
  const cadenceLabel=(t)=>{
    if(t.cadence==='hourly') return `كل ساعة عند الدقيقة ${String(t.minute_utc).padStart(2,'0')}`;
    if(t.cadence==='daily') return `يوميًا ${String(t.hour_utc).padStart(2,'0')}:${String(t.minute_utc).padStart(2,'0')} UTC`;
    const days=['الاثنين','الثلاثاء','الأربعاء','الخميس','الجمعة','السبت','الأحد'];
    return `${days[t.weekday_utc]||'أسبوعيًا'} ${String(t.hour_utc).padStart(2,'0')}:${String(t.minute_utc).padStart(2,'0')} UTC`;
  };
  const button=(text,action,id,cls='ghost')=>{const b=document.createElement('button');b.type='button';b.className=cls;b.dataset.action=action;b.dataset.id=id;b.textContent=text;return b;};
  const render=()=>{
    list.replaceChildren();
    if(!tasks.length){const e=document.createElement('div');e.className='empty-state';e.textContent='لا توجد مهام مجدولة حتى الآن.';list.append(e);return;}
    for(const t of tasks){
      const row=document.createElement('div');row.className='schedule-item';row.dataset.id=t.id;
      const main=document.createElement('div');main.className='schedule-main';
      const strong=document.createElement('strong');strong.textContent=`${t.domain} · ${t.task_type==='backup_site'?'Site Backup':'Git Deploy'}`;
      const sub=document.createElement('span');sub.textContent=`${cadenceLabel(t)} · ${t.enabled?'مفعلة':'متوقفة'}`;main.append(strong,sub);
      const run=document.createElement('div');run.className='schedule-run';const sm=document.createElement('small');sm.textContent=when(t.last_run);const st=document.createElement('b');st.className=t.last_status;st.textContent=t.run_requested?'QUEUED':String(t.last_status||'never').toUpperCase();run.append(sm,st);
      const acts=document.createElement('div');acts.className='schedule-actions';acts.append(button('تشغيل الآن','run',t.id,'tiny royal-action'),button(t.enabled?'إيقاف':'تفعيل','toggle',t.id,'tiny ghost'),button('حذف','delete',t.id,'tiny danger'));
      row.append(main,run,acts);list.append(row);
    }
  };
  const load=async()=>{
    try{const b=await api('/api/schedules');tasks=b.tasks||[];quota.textContent=`${tasks.length} / ${b.max_cron_jobs??'—'}`;render();}
    catch(e){list.innerHTML='';const d=document.createElement('div');d.className='empty-state';d.textContent=e.message;list.append(d);}
  };
  const syncFields=()=>{const c=cadence.value;hour.disabled=c==='hourly';weekday.disabled=c!=='weekly';};
  cadence.addEventListener('change',syncFields);syncFields();

  form.addEventListener('submit',async(e)=>{
    e.preventDefault();say('جاري إنشاء المهمة…');
    const payload={domain:domain.value,task_type:taskType.value,cadence:cadence.value,hour_utc:Number(hour.value||0),minute_utc:Number(minute.value||0),weekday_utc:Number(weekday.value||0),enabled:true};
    try{await api('/api/schedules',{method:'POST',body:JSON.stringify(payload)});say('تم إنشاء المهمة المجدولة.','ok');await load();}
    catch(err){say(err.message.includes('step-up')?'يلزم تفعيل Step-Up من صفحة الأمن أولًا.':err.message,'error');}
  });

  list.addEventListener('click',async(e)=>{
    const b=e.target.closest('button[data-action]');if(!b)return;const id=Number(b.dataset.id);const t=tasks.find(x=>x.id===id);if(!t)return;b.disabled=true;
    try{
      if(b.dataset.action==='run') await api(`/api/schedules/${id}/run`,{method:'POST',body:'{}'});
      else if(b.dataset.action==='toggle') await api(`/api/schedules/${id}`,{method:'PUT',body:JSON.stringify({enabled:!t.enabled})});
      else if(b.dataset.action==='delete'){if(!confirm('حذف هذه المهمة المجدولة؟')){b.disabled=false;return;}await api(`/api/schedules/${id}`,{method:'DELETE'});}
      say('تم تحديث Scheduled Tasks.','ok');await load();
    }catch(err){say(err.message.includes('step-up')?'يلزم Step-Up Authentication قبل هذه العملية.':err.message,'error');b.disabled=false;}
  });

  load();
})();
