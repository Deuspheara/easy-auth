'use strict';
(async () => {
  const form = document.getElementById('delivery');
  const body = new URLSearchParams(new FormData(form));
  form.remove();
  try {
    const response = await fetch('/v1/saml/sign-in/finish', {
      method: 'POST', credentials: 'same-origin', cache: 'no-store', body
    });
    if (!response.ok) throw new Error();
    window.location.replace('/');
  } catch {
    document.getElementById('status').textContent = 'Unable to complete sign-in. Return to sign-in and try again.';
  }
})();
