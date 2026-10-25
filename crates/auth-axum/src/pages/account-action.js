"use strict";
import {feedback, locateFeedback, fieldError} from "/ui/feedback.js";
const form=document.getElementById("action-form");
const button=document.getElementById("confirm");
let token;
function readProof() {
  locateFeedback(form);
  token=new URLSearchParams(location.hash.slice(1)).get("token");
  history.replaceState(null,"",location.pathname);
  button.disabled=!token;form.hidden=false;
  feedback(token ? "Confirm only if you requested this action." : "Open the confirmation email in the requesting browser.");
}
window.addEventListener("hashchange",readProof);readProof();
form.addEventListener("submit",async event=>{
  event.preventDefault();
  locateFeedback(form);
  const deleting=form.dataset.action==="delete";
  const body={token};
  if(deleting) {
    body.confirmation=document.getElementById("confirmation").value;
    if(body.confirmation!=="delete my account") {const input=document.getElementById("confirmation");fieldError(input,"Enter the exact confirmation phrase.");input.focus();return;}
  }
  button.disabled=true;feedback("Confirming…");
  try {
    const response=await fetch(deleting ? "/v1/account/delete/finish" : "/v1/account/email/confirm",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
    if(!response.ok) {feedback("Unable to confirm. Sign in again and restart the requested action.", true);button.disabled=false;return;}
    token=null;form.hidden=true;
    feedback(response.status===202 ? "This address is confirmed. Open and confirm the other email link in this browser." : deleting ? "Authentication account deleted." : "Email changed. Sign in again with your new email.");
  } catch {feedback("Authentication is temporarily unavailable. Try again.", true);button.disabled=false;}
});
