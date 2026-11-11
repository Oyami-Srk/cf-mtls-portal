'use strict';
(() => {
  const $ = id => document.getElementById(id);
  let session, privateState, packageUrl, renewalId, pendingRevoke, busy = false;
  const labels = {active:'可用',revoked:'已撤销',pending_revocation:'正在撤销',pending_reactivation:'正在启用',unverified:'状态待核对',issuing:'正在签发',issue_uncertain:'需核对签发结果',issued_pending_allow:'等待开通',revocation_pending:'撤销未完成',blocked_pending_revoke:'已禁止访问，待撤销',manual_review:'需人工核对',failed:'未签发'};
  const guides = {
    android:['下载 .p12 文件。','在系统设置中搜索“安装证书”，选择“VPN 和应用”等客户端身份选项，导入文件并输入导入密码。不要选择安装 CA 证书。','使用支持客户端证书的浏览器访问 mTLS 入口，按提示选择证书。部分应用内浏览器不支持。'],
    ios:['使用 Safari 下载 .p12 文件，保存到“文件”。','打开该文件，按系统提示前往“设置”，安装下载的客户端身份并输入导入密码。无需安装根 CA。','使用 Safari 访问 mTLS 入口，选择对应的设备证书。'],
    windows:['下载并双击 .p12 文件。','在导入向导中选择“当前用户”，输入导入密码，将证书导入“个人”证书库。无需设置为可导出或安装根 CA。','使用 Edge 或 Chrome 访问 mTLS 入口，选择对应的设备证书。'],
    mac:['下载 .p12 文件并用“钥匙串访问”打开。','将身份导入“登录”钥匙串，输入导入密码。无需设置为受信任的根 CA。','使用 Safari 等支持系统客户端身份的浏览器访问 mTLS 入口。']
  };
  function notice(text, error = false) { $('notice').textContent=text; $('notice').hidden=!text; $('notice').classList.toggle('error',error); }
  function guide() { $('install-steps').replaceChildren(...guides[$('device-type').value].map(text=>{const li=document.createElement('li');li.textContent=text;return li;})); }
  const device = /Android/i.test(navigator.userAgent)?'android':/iPhone|iPad/i.test(navigator.userAgent)?'ios':/Win/i.test(navigator.userAgent)?'windows':'mac';
  $('device-type').value=device;guide();$('device-type').addEventListener('change',guide);
  async function api(path, method='GET', data) {
    const response=await fetch(path,{method,credentials:'same-origin',cache:'no-store',headers:{'Content-Type':'application/json',...(session?{'X-CSRF-Token':session.csrf}:{})},body:data===undefined?undefined:JSON.stringify(data)});
    let value;try {value=await response.json();}catch {throw new Error('服务器没有返回完整结果，请核对设备列表。');}
    if(!response.ok) {if(response.status===401 && !privateState){$('workspace').hidden=true;$('login-panel').hidden=false;$('logout').hidden=true;}throw new Error(value.error || '操作未完成，请核对设备状态。');}return value;
  }
  function date(value){return value?new Date(value).toLocaleDateString('zh-CN'):'—';}
  function action(text,fn){const button=document.createElement('button');button.type='button';button.className='link';button.textContent=text;button.addEventListener('click',()=>{if(busy)return;Promise.resolve(fn()).catch(error=>notice(error.message,true));});return button;}
  function discard(){if(privateState && !confirm('确认清除本次申请的本机密钥？未保存的私钥将无法找回。已签发证书仍需在列表中撤销。'))return false;reset();return true;}
  async function devices(){
    const result=await api('/api/devices');const entries=[...result.pinned,...result.devices.map(x=>({...x,managed:true}))];
    const rows=entries.map(item=>{
      const row=document.createElement('tr'),name=document.createElement('td'),status=document.createElement('td'),expires=document.createElement('td'),actions=document.createElement('td');
      const title=document.createElement('div');title.className='device-name';title.textContent=item.name;
      const fingerprint=document.createElement('div');fingerprint.className='fingerprint';fingerprint.textContent=item.fingerprint?item.fingerprint.slice(0,12)+'…':'';fingerprint.title=item.fingerprint || '';name.append(title,fingerprint);
      status.textContent=labels[item.status] || '状态待核对';if(item.status!=='active')status.className='warning';expires.textContent=date(item.expiresAt);
      const group=document.createElement('div');group.className='device-actions';
      if(item.managed && item.status==='active')group.append(action('续签',()=>{if(privateState && !discard())return;renewalId=item.id;$('device-name').value=item.name;$('enroll-title').textContent='续签证书';$('renew-note').hidden=false;window.scrollTo({top:0,behavior:'auto'});}));
      if(item.managed && ['issued_pending_allow','issue_uncertain','issuing'].includes(item.status))group.append(action(item.status==='issued_pending_allow'?'重试开通':'核对结果',async()=>{setBusy(true,'正在核对');try{await api(`/api/devices/${item.id}/${item.status==='issued_pending_allow'?'retry':'recover'}`,'POST',{});await devices();await recoverPackage(item.id);notice('证书状态已核对。');}finally{setBusy(false);}}));
      if(item.managed && ['active','issued_pending_allow','revocation_pending','blocked_pending_revoke'].includes(item.status))group.append(action('撤销',()=>{pendingRevoke=item;$('confirm-message').textContent='设备：'+item.name;$('confirm-dialog').showModal();}));
      if(!item.managed){const text=document.createElement('span');text.className='muted';text.textContent='既有证书';group.append(text);}
      actions.append(group);row.append(name,status,expires,actions);return row;
    });$('device-list').replaceChildren(...rows);$('empty-list').hidden=entries.length>0;
  }
  function setBusy(value,text=''){busy=value;$('issue-button').disabled=value || !session?.configured || !!privateState;$('progress').hidden=!value;$('progress').textContent=text;$('clear-request').disabled=value;$('logout').disabled=value || !!privateState;}
  function reset(){if(packageUrl)URL.revokeObjectURL(packageUrl);packageUrl=undefined;privateState=undefined;renewalId=undefined;$('enroll-form').reset();$('device-type').value=device;$('import-password').type='password';$('show-password').textContent='显示密码';$('enroll-form').hidden=false;$('download-panel').hidden=true;$('clear-request').hidden=true;$('renew-note').hidden=true;$('enroll-title').textContent='签发证书';guide();setBusy(false);}
  function binary(bytes){let out='';for(let offset=0;offset<bytes.length;offset+=8192)out+=String.fromCharCode(...bytes.subarray(offset,offset+8192));return out;}
  function pack(certificate,password){
    const cert=forge.pki.certificateFromPem(certificate);
    if(cert.publicKey.n.toString(16)!==privateState.publicKey.n.toString(16) || cert.publicKey.e.toString(16)!==privateState.publicKey.e.toString(16))throw new Error('证书公钥不匹配，未打包私钥。');
    const p12=forge.pkcs12.toPkcs12Asn1(privateState.privateKey,[cert],password,{algorithm:'aes256',count:100000,saltSize:16,useMac:true,friendlyName:'mTLS · '+privateState.name,generateLocalKeyId:true});
    const output=Uint8Array.from(forge.asn1.toDer(p12).getBytes(),c=>c.charCodeAt(0));
    if(packageUrl)URL.revokeObjectURL(packageUrl);packageUrl=URL.createObjectURL(new Blob([output],{type:'application/x-pkcs12'}));output.fill(0);
    $('retry-package').hidden=true;$('download-p12').disabled=false;
  }
  async function recoverPackage(id){if(privateState?.deviceId!==id)return;const result=await api(`/api/devices/${id}/certificate`);if(!result.certificate)return;privateState.certificate=result.certificate;$('enroll-form').hidden=true;$('download-panel').hidden=false;$('download-summary').textContent='证书已签发。请重新打包并保存文件。';$('retry-package').hidden=false;$('download-p12').disabled=!packageUrl;}
  $('generate-password').addEventListener('click',()=>{if(busy)return;const bytes=crypto.getRandomValues(new Uint8Array(18));const password=btoa(binary(bytes)).replaceAll('+','-').replaceAll('/','_');$('import-password').value=password;$('confirm-password').value=password;notice('已生成随机密码。请显示并保存，安装时需要输入。');});
  $('show-password').addEventListener('click',()=>{const show=$('import-password').type==='password';$('import-password').type=show?'text':'password';$('show-password').textContent=show?'隐藏密码':'显示密码';});
  $('enroll-form').addEventListener('submit',async event=>{
    event.preventDefault();if(busy || privateState)return;notice('');let password=$('import-password').value;
    if(password.length<16 || password.length>128 || password!==$('confirm-password').value){notice('导入密码需要 16–128 个字符，且两次输入一致。',true);return;}
    if(!window.isSecureContext || !crypto.subtle){notice('请使用支持 WebCrypto 的浏览器，通过 HTTPS 打开页面。',true);return;}
    const name=$('device-name').value.trim();
    try{
      setBusy(true,'正在生成密钥');
      const key=await crypto.subtle.generateKey({name:'RSASSA-PKCS1-v1_5',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['sign','verify']);
      const pkcs8=new Uint8Array(await crypto.subtle.exportKey('pkcs8',key.privateKey)),spki=new Uint8Array(await crypto.subtle.exportKey('spki',key.publicKey));
      try{privateState={name,privateKey:forge.pki.privateKeyFromAsn1(forge.asn1.fromDer(binary(pkcs8))),publicKey:forge.pki.publicKeyFromAsn1(forge.asn1.fromDer(binary(spki)))};}finally{pkcs8.fill(0);}
      $('clear-request').hidden=false;
      const job=await api('/api/jobs','POST',{name,...(renewalId?{replacedId:renewalId}:{})});privateState.deviceId=job.deviceId;
      const csr=forge.pki.createCertificationRequest();csr.publicKey=privateState.publicKey;csr.setSubject([{name:'commonName',value:job.cn}]);csr.sign(privateState.privateKey,forge.md.sha256.create());
      setBusy(true,'正在签发证书');const issued=await api('/api/issue','POST',{jobId:job.jobId,csr:forge.pki.certificationRequestToPem(csr)});privateState.certificate=issued.certificate;
      setBusy(true,'正在加密文件');await new Promise(resolve=>requestAnimationFrame(resolve));pack(issued.certificate,password);
      $('enroll-form').hidden=true;$('download-panel').hidden=false;$('download-summary').textContent=name+' · 到期 '+date(issued.device.expiresAt);
      notice('证书已签发，请下载并安装。');await devices();
    }catch(error){notice(error.message,true);try{await devices();if(privateState?.deviceId)await recoverPackage(privateState.deviceId);}catch{} }
    finally{password='';$('import-password').value='';$('confirm-password').value='';setBusy(false);}
  });
  $('download-p12').addEventListener('click',()=>{if(!packageUrl)return;const link=document.createElement('a');link.href=packageUrl;link.download='mtls-'+(privateState.name || 'device').replace(/[^\p{L}\p{N}_-]/gu,'_')+'.p12';document.body.append(link);link.click();link.remove();});
  $('retry-package').addEventListener('click',()=>{if(!privateState?.certificate)return;let password=prompt('设置本次文件的导入密码（16–128 个字符）');if(!password)return;if(password.length<16 || password.length>128){notice('密码长度不符合要求。',true);return;}try{pack(privateState.certificate,password);notice('文件已重新打包，可以下载。');}catch{notice('打包未完成，请保留页面并核对浏览器。',true);}finally{password='';}});
  $('clear-request').addEventListener('click',()=>{if(!busy)discard();});$('new-device').addEventListener('click',()=>{if(confirm('确认已经保存证书文件及导入密码？完成后将清除本机临时密钥。')){reset();notice('');}});
  $('refresh-devices').addEventListener('click',()=>devices().catch(error=>notice(error.message,true)));
  $('cancel-revoke').addEventListener('click',()=>$('confirm-dialog').close());
  $('confirm-revoke').addEventListener('click',async()=>{if(busy)return;setBusy(true,'正在撤销');$('confirm-revoke').disabled=true;try{await api(`/api/devices/${pendingRevoke.id}/revoke`,'POST',{});notice('证书已撤销。');}catch(error){notice(error.message,true);}finally{$('confirm-dialog').close();$('confirm-revoke').disabled=false;setBusy(false);await devices().catch(()=>{});}});
  $('check-connection').addEventListener('click',async()=>{try{await api('/api/check','POST',{});notice('连接和防护规则正常。');}catch(error){notice(error.message,true);}});
  $('logout').addEventListener('click',async()=>{if(privateState || busy)return;try{await api('/api/logout','POST',{});location.assign('/');}catch(error){notice(error.message,true);}});
  window.addEventListener('beforeunload',event=>{if(privateState || busy){event.preventDefault();event.returnValue='';}});
  (async()=>{try{session=await api('/api/session');$('user-name').textContent=session.name;$('workspace').hidden=false;$('login-panel').hidden=true;$('logout').hidden=false;$('validity').textContent='有效期 '+session.validityDays+' 天';$('connection-status').textContent=session.configured?'已配置签发服务。':'签发服务尚未配置，请联系管理员。';setBusy(false);await devices();}catch(error){if(!error.message.includes('请先登录'))notice(error.message,true);}})();
})();
