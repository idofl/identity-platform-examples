/**
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

function GcipAuthHelper(apiKey, baseUrl) { 
  this.gcipUser = null;
  this.authHandlerUrl = baseUrl + this.authHandlerPath;
  this.signedInHandler = function() {};
} 

GcipAuthHelper.prototype.identityPlatformBaseUrl = 'https://identitytoolkit.googleapis.com/v1';
GcipAuthHelper.prototype.authHandlerPath = '/auth-handler';

GcipAuthHelper.prototype.init = function() {
  // Set up for popup notifications
  $(window).on('message', (event) => {
    if (event.originalEvent.origin == window.location.origin) {
      var data = event.originalEvent.data;
      this.signInWithIdp(data);      
    }
  });

  // Set up for redirect (relevant if already been redirected back)
  var data = localStorage.getItem('authResponse');
  if (data)
  {
    localStorage.removeItem('authResponse');
    this.signInWithIdp(data);    
  }
}

GcipAuthHelper.prototype.signInWithPopup = function(tenantId, providerId) {
  // Get URL of IdP, and open it in a popup
  this.createAuthUri(tenantId, providerId)  
  .then(authUriResponse => {
    this.storeAuthState(tenantId, providerId, authUriResponse.sessionId);
    var popup = window.open(authUriResponse.authUri);
    if(popup !== null && !popup.closed)
      popup.focus();
  });
}

GcipAuthHelper.prototype.signInWithRedirect = function(tenantId, providerId) {  
  // Get URL of IdP, and redirect the browser to it
  this.createAuthUri(tenantId, providerId)
    .then(authUriResponse => {
      this.storeAuthState(tenantId, providerId, authUriResponse.sessionId);
      localStorage.setItem('onSuccessfulAuthRedirect', window.location.href);
      window.location.href = authUriResponse.authUri;
    });
}

GcipAuthHelper.prototype.storeAuthState = function(tenantId, providerId, sessionId) {
  localStorage.setItem('signInWithIdpParams', JSON.stringify({ 
    'tenantId' : tenantId,
    'providerId' : providerId,
    'sessionId' : sessionId,
    'authHandlerUrl' : this.authHandlerUrl
  }));
}

GcipAuthHelper.prototype.getAuthState = function() {
  var authState = JSON.parse(localStorage.getItem('signInWithIdpParams'));
  localStorage.removeItem('signInWithIdpParams');
  return authState;
}

GcipAuthHelper.prototype.createAuthUri = function(tenantId, providerId) {
  // https://cloud.google.com/identity-platform/docs/reference/rest/v1/accounts/createAuthUri
  const createAuthUriUrl = `${this.identityPlatformBaseUrl}/accounts:createAuthUri?key=${config.apiKey}`;
  const request = {
    'providerId' : providerId,
    'tenantId' : tenantId,
    'continueUri' : this.authHandlerUrl,
  };

  return fetch(
      createAuthUriUrl,
      {
        contentType: 'application/json',
        method: 'POST',
        body: JSON.stringify(request)
      }
    )
  .then(response => response.json())
  .then(data => {
    //var authUri = data.authUri;    
    return {
      "authUri" : data.authUri,
      "sessionId" : data.sessionId
    };
  });
};

GcipAuthHelper.prototype.signOut = function() {
  this.gcipUser = null; 
}

GcipAuthHelper.prototype.signInWithIdp = function(data) {
  authState = this.getAuthState();
  this.authHandlerUrl = authState.authHandlerUrl;

  // https://cloud.google.com/identity-platform/docs/reference/rest/v1/accounts/signInWithIdp
  const signInWithIdpUrl = `${this.identityPlatformBaseUrl}/accounts:signInWithIdp?key=${config.apiKey}`;

  const request = {
      'requestUri' : this.authHandlerUrl,      
      'sessionId' : authState.sessionId,
      'returnRefreshToken' : true,
      'returnSecureToken' : true,
      'tenantId' : authState.tenantId
    };

  if (authState.providerId == 'google.com' || authState.providerId.startsWith('saml.')) {
    request.postBody = `${data}&providerId=${authState.providerId}`;    
  } else {
    throw new Error('This sample script only supports the google.com and SAML providers for GCIP');
  }
  
  fetch(
      signInWithIdpUrl,
      {
        contentType: 'application/json',
        method: 'POST',
        body: JSON.stringify(request)
      }
    )
  .then(response => response.json())
  .then(data => {
    this.gcipUser = data;
    this.signedInHandler(this.gcipUser);    
  });
}

GcipAuthHelper.prototype.isSignedIn = function() {
    return (this.gcipUser && this.gcipUser.idToken);
}

GcipAuthHelper.prototype.getIdToken = function() {
  var token = this.jwtDecode(this.gcipUser.idToken);

  // If exp has passed, refresh the token
  if (Date.now() < token.payload.exp * 1000) {
    return this.refreshToken(this.gcipUser.refreshToken);
  }  
  return Promise.resolve(this.gcipUser.idToken);
}

GcipAuthHelper.prototype.refreshToken = function(refreshToken) {
  // https://cloud.google.com/identity-platform/docs/reference/rest/client#section-refresh-token
  const tokenUrl = `https://securetoken.googleapis.com/v1/token?key=${config.apiKey}`;
  const requestBody = new URLSearchParams(`grant_type=refresh_token&refresh_token=${refreshToken}`);

  return fetch(
      tokenUrl,
      {
        contentType: 'application/x-www-form-urlencoded',
        method: 'POST',
        body: requestBody
      }
    )
  .then(response => response.json())
  .then(data => {    
    this.gcipUser.idToken = data.id_token;
    this.gcipUser.refreshToken = data.refresh_token;   
    return this.gcipUser.idToken; 
  });
}

GcipAuthHelper.prototype.jwtDecode = function(t) {
  var token = {};
  token.raw = t;
  token.header = JSON.parse(window.atob(t.split('.')[0]));
  token.payload = JSON.parse(window.atob(t.split('.')[1]));
  return token;
}

GcipAuthHelper.prototype.onSignedIn = function(handler) {
    this.signedInHandler = handler;
};
