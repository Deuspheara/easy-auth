"use strict";
const form=document.getElementById("action-form");
const button=document.getElementById("confirm");
const status=document.getElementById("status");
let token;
function readProof() {
  token=new URLSearchParams(location.hash.slice(1)).get("token");
  history.replaceState(null,"",location.pathname);
  button.disabled=!token;form.hidden=false;
  status.textContent=token ? "Confirm only if you requested this action." : "Open the confirmation email in the requesting browser.";
}
window.addEventListener("hashchange",readProof);readProof();
form.addEventListener("submit",async event=>{
  event.preventDefault();
  const deleting=form.dataset.action==="delete";
  const body={token};
  if(deleting) {
    body.confirmation=document.getElementById("confirmation").value;
    if(body.confirmation!=="delete my account") {status.textContent="Enter the exact confirmation phrase.";return;}
  }
  button.disabled=true;status.textContent="Confirming…";
  try {
    const response=await fetch(deleting ? "/v1/account/delete/finish" : "/v1/account/email/confirm",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
    if(!response.ok) {status.textContent="Unable to confirm. Sign in again and restart the requested action.";button.disabled=false;return;}
    token=null;form.hidden=true;
    status.textContent=response.status===202 ? "This address is confirmed. Open and confirm the other email link in this browser." : deleting ? "Authentication account deleted." : "Email changed. Sign in again with your new email.";
  } catch {status.textContent="Authentication is temporarily unavailable. Try again.";button.disabled=false;}
});
