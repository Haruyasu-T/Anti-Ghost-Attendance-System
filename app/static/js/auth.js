// SPDX-FileCopyrightText: 2026 田中晴康
// SPDX-License-Identifier: Apache-2.0

"use strict";
const form=document.querySelector("#login-form"),errorBox=document.querySelector("#login-error");
form&&form.addEventListener("submit",async function(event){
 event.preventDefault();errorBox.hidden=true;if(!form.reportValidity())return;
 const button=form.querySelector("button[type=submit]");button.disabled=true;
 try {
  const response=await fetch("/auth/login",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify({login_id:form.login_id.value.trim(),password:form.password.value})});
  if(!response.ok){errorBox.textContent=response.status===429?"しばらく待ってから再度お試しください。":"IDまたはパスワードが正しくありません。";errorBox.hidden=false;return;}
  // 遷移先は "/" に任せる。ロールごとの入口はサーバー側の index が決めており、
  // ここに同じ分岐を書くと、ロールが増えたときに片方だけ古くなる（admin を
  // 足したときに実際そうなった）。
  window.location.assign("/");
 } catch(e){errorBox.textContent="通信できませんでした。接続を確認してもう一度お試しください。";errorBox.hidden=false;}
 finally {button.disabled=false;}
});
