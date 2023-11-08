// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package com.azuresamples.msalandroidapp;

import android.os.Bundle;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.Spinner;
import android.widget.TextView;

import com.android.volley.AuthFailureError;
import com.android.volley.DefaultRetryPolicy;
import com.android.volley.Request;
import com.android.volley.RequestQueue;
import com.android.volley.toolbox.DiskBasedCache;
import com.android.volley.toolbox.JsonArrayRequest;
import com.android.volley.toolbox.JsonObjectRequest;
import com.android.volley.toolbox.Volley;
import com.microsoft.identity.client.AcquireTokenParameters;
import com.microsoft.identity.client.AuthenticationCallback;
import com.microsoft.identity.client.IAccount;
import com.microsoft.identity.client.IAuthenticationResult;
import com.microsoft.identity.client.IMultipleAccountPublicClientApplication;
import com.microsoft.identity.client.IPublicClientApplication;
import com.microsoft.identity.client.Prompt;
import com.microsoft.identity.client.PublicClientApplication;
import com.microsoft.identity.client.SilentAuthenticationCallback;
import com.microsoft.identity.client.exception.MsalClientException;
import com.microsoft.identity.client.exception.MsalException;
import com.microsoft.identity.client.exception.MsalServiceException;
import com.microsoft.identity.client.exception.MsalUiRequiredException;

import org.json.JSONException;
import org.json.JSONObject;
import org.unbrokendome.base62.Base62;

import java.nio.ByteBuffer;
import java.nio.LongBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 * Implementation sample for 'B2C' mode.
 */
public class B2CModeFragment extends Fragment {
    private static final String TAG = B2CModeFragment.class.getSimpleName();
    private static final String GET_LICENSES_API_URL = "https://licenses.acmeaom.com/v1/licenses";
    private static final String REGISTER_INSTALLS_API_URL = "https://installs.acmeaom.com/google/v1/installs";

    // This key is for the example only and will be deleted once the system is in production.
    private static final String REGISTER_INSTALLS_API_KEY = "U2uGxAalatnyClDazRCcLccS3I3s6bfTCDaDxjCSFC96AzFuBwhR0A==";

    private RequestQueue requestQueue;

    /* UI & Debugging Variables */
    Button removeAccountButton;
    Button runUserFlowButton;
    Button acquireTokenSilentButton;
    TextView graphResourceTextView;
    TextView logTextView;
    Spinner policyListSpinner;
    Spinner b2cUserList;

    private List<B2CUser> users;

    /* Azure AD Variables */
    private IMultipleAccountPublicClientApplication b2cApp;


    @Override
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        requestQueue = Volley.newRequestQueue(getContext());
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        // Inflate the layout for this fragment
        final View view = inflater.inflate(R.layout.fragment_b2c_mode, container, false);
        initializeUI(view);

        // Creates a PublicClientApplication object with res/raw/auth_config_single_account.json
        PublicClientApplication.createMultipleAccountPublicClientApplication(getContext(),
                R.raw.auth_config_b2c,
                new IPublicClientApplication.IMultipleAccountApplicationCreatedListener() {
                    @Override
                    public void onCreated(IMultipleAccountPublicClientApplication application) {
                        b2cApp = application;
                        loadAccounts();
                    }

                    @Override
                    public void onError(MsalException exception) {
                        displayError(exception);
                        removeAccountButton.setEnabled(false);
                        runUserFlowButton.setEnabled(false);
                        acquireTokenSilentButton.setEnabled(false);
                    }
                });

        return view;
    }

    /**
     * Initializes UI variables and callbacks.
     */
    private void initializeUI(@NonNull final View view) {
        removeAccountButton = view.findViewById(R.id.btn_removeAccount);
        runUserFlowButton = view.findViewById(R.id.btn_runUserFlow);
        acquireTokenSilentButton = view.findViewById(R.id.btn_acquireTokenSilently);
        graphResourceTextView = view.findViewById(R.id.msgraph_url);
        logTextView = view.findViewById(R.id.txt_log);
        policyListSpinner = view.findViewById(R.id.policy_list);
        b2cUserList = view.findViewById(R.id.user_list);

        final ArrayAdapter<String> dataAdapter = new ArrayAdapter<>(
                getContext(), android.R.layout.simple_spinner_item,
                new ArrayList<String>() {{
                    for (final String policyName : B2CConfiguration.Policies)
                        add(policyName);
                }}
        );

        dataAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        policyListSpinner.setAdapter(dataAdapter);
        dataAdapter.notifyDataSetChanged();

        runUserFlowButton.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                if (b2cApp == null) {
                    return;
                }

                /**
                 * Runs user flow interactively.
                 * <p>
                 * Once the user finishes with the flow, you will also receive an access token containing the claims for the scope you passed in (see B2CConfiguration.getScopes()),
                 * which you can subsequently use to obtain your resources.
                 */

                AcquireTokenParameters parameters = new AcquireTokenParameters.Builder()
                        .startAuthorizationFromActivity(getActivity())
                        .fromAuthority(B2CConfiguration.getAuthorityFromPolicyName(policyListSpinner.getSelectedItem().toString()))
                        .withScopes(B2CConfiguration.getScopes())
                        .withPrompt(Prompt.LOGIN)
                        .withCallback(getAuthInteractiveCallback())
                        .build();

                b2cApp.acquireToken(parameters);

            }
        });

        acquireTokenSilentButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (b2cApp == null) {
                    return;
                }

                final B2CUser selectedUser = users.get(b2cUserList.getSelectedItemPosition());
                selectedUser.acquireTokenSilentAsync(b2cApp,
                        policyListSpinner.getSelectedItem().toString(),
                        B2CConfiguration.getScopes(),
                        getAuthSilentCallback());
            }
        });

        removeAccountButton.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                if (b2cApp == null) {
                    return;
                }

                final B2CUser selectedUser = users.get(b2cUserList.getSelectedItemPosition());
                selectedUser.signOutAsync(b2cApp,
                        new IMultipleAccountPublicClientApplication.RemoveAccountCallback() {
                            @Override
                            public void onRemoved() {
                                logTextView.setText("Signed Out.");
                                loadAccounts();
                            }

                            @Override
                            public void onError(@NonNull MsalException exception) {
                                displayError(exception);
                            }
                        });
            }
        });
    }

    /**
     * Load signed-in accounts, if there's any.
     */
    private void loadAccounts() {
        if (b2cApp == null) {
            return;
        }

        b2cApp.getAccounts(new IPublicClientApplication.LoadAccountsCallback() {
            @Override
            public void onTaskCompleted(final List<IAccount> result) {
                users = B2CUser.getB2CUsersFromAccountList(result);
                updateUI(users);
            }

            @Override
            public void onError(MsalException exception) {
                displayError(exception);
            }
        });
    }


    /**
     * Example of hitting one of the API endpoints. This is just test code,
     * not suitable for production and not intended to be used as a reference
     * or suggestion of usage.
    */
    private void getLicenses(@NonNull final IAuthenticationResult result) {
        logTextView.append("\nRetrieving available licenses for user...");

        JsonArrayRequest request = new JsonArrayRequest(
                Request.Method.GET,
                GET_LICENSES_API_URL,
                null,
                response -> {
                    // Send to UI
                    Log.d(TAG, "Success from API call.");

                    final String output =
                            "\n\nLicenses for the signed-in user :\n" +
                            response.toString();
                    logTextView.append(output);
                },
                error -> {
                    // Error hitting API
                    Log.d(TAG, "Error getting licenses. " + error.getMessage());
                }) {
                    @Override
                    public Map<String, String> getHeaders() throws AuthFailureError {
                        Map<String, String> headers = new HashMap<>();

                        headers.put("Authorization", "Bearer " + result.getAccessToken());
                        return headers;
                    }
        };

        // For testing we don't really do retries. In production, the policy should
        // enforce exponential backoff (e.g. by using a suitable backoff multiplier.)
        request.setRetryPolicy(new DefaultRetryPolicy(
                3000,
                DefaultRetryPolicy.DEFAULT_MAX_RETRIES,
                DefaultRetryPolicy.DEFAULT_BACKOFF_MULT
        ));

        requestQueue.add(request);
    }


    private void registerInstall(@NonNull final IAuthenticationResult result) {
        logTextView.append("\nRegistering install for user...");

        // Build body by hand for simplicity
        JSONObject registration = new JSONObject();
        try {
            registration.put("vid", "44444444444444444444444444444444");
            registration.put("iid", UUID.randomUUID().toString().replaceAll("-", ""));
            registration.put("cid", generateCID());
            registration.put("aid", "" );

            // ID includes sign-in flow, we only want OID. Also API wants OID to be only alphanumeric.
            registration.put("oid",
                    result.getAccount().getId().replaceAll("-", "").substring(0, 32));

        } catch (JSONException e) {
            throw new RuntimeException(e);
        }

        JsonObjectRequest request = new JsonObjectRequest(
                Request.Method.PUT,
                REGISTER_INSTALLS_API_URL,
                registration,
                response -> {
                    // Send to UI
                    Log.d(TAG, "Success from API call.");

                    final String output =
                            "\n\nRegistration response :\n" +
                                    response.toString();
                    logTextView.append(output);
                },
                error -> {
                    // Error hitting API
                    Log.d(TAG, "Error getting licenses. " + error.getMessage());
                }) {
            @Override
            public Map<String, String> getHeaders() throws AuthFailureError {
                Map<String, String> headers = new HashMap<>();

                headers.put("x-functions-key", REGISTER_INSTALLS_API_KEY);
                return headers;
            }
        };

        // For testing we don't really do retries. In production, the policy should
        // enforce exponential backoff (e.g. by using a suitable backoff multiplier.)
        request.setRetryPolicy(new DefaultRetryPolicy(
                3000,
                DefaultRetryPolicy.DEFAULT_MAX_RETRIES,
                DefaultRetryPolicy.DEFAULT_BACKOFF_MULT
        ));

        requestQueue.add(request);
    }


    // This is not meant to be a reference or example implementation.
    // I cobbled it together from the Interwebs. A production-worthy
    // implementation is likely to be different.
    private String generateCID() {
        KeyGenerator keyGen;
        try {
            keyGen = KeyGenerator.getInstance("HmacSHA512");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        SecureRandom secureRandom = new SecureRandom();
        keyGen.init(secureRandom);
        SecretKey key = keyGen.generateKey();

        // Notion dos mentions Base62, but Base64 is okay too.
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    /**
     * Callback used in for silent acquireToken calls.
     */
    private SilentAuthenticationCallback getAuthSilentCallback() {
        return new SilentAuthenticationCallback() {

            @Override
            public void onSuccess(IAuthenticationResult authenticationResult) {
                Log.d(TAG, "Successfully authenticated");

                /* Successfully got a token. */
                displayResult(authenticationResult);
                getLicenses(authenticationResult);
                registerInstall(authenticationResult);
            }

            @Override
            public void onError(MsalException exception) {
                /* Failed to acquireToken */
                Log.d(TAG, "Authentication failed: " + exception.toString());
                displayError(exception);

                if (exception instanceof MsalClientException) {
                    /* Exception inside MSAL, more info inside MsalError.java */
                } else if (exception instanceof MsalServiceException) {
                    /* Exception when communicating with the STS, likely config issue */
                } else if (exception instanceof MsalUiRequiredException) {
                    /* Tokens expired or no session, retry with interactive */
                }
            }
        };
    }

    /**
     * Callback used for interactive request.
     * If succeeds we use the access token to call the Microsoft Graph.
     * Does not check cache.
     */
    private AuthenticationCallback getAuthInteractiveCallback() {
        return new AuthenticationCallback() {

            @Override
            public void onSuccess(IAuthenticationResult authenticationResult) {
                /* Successfully got a token, use it to call a protected resource - MSGraph */
                Log.d(TAG, "Successfully authenticated");

                /* display result info */
                displayResult(authenticationResult);

                /* Reload account asynchronously to get the up-to-date list. */
                loadAccounts();

                getLicenses(authenticationResult);
                registerInstall(authenticationResult);
            }

            @Override
            public void onError(MsalException exception) {
                final String B2C_PASSWORD_CHANGE = "AADB2C90118";
                if (exception.getMessage().contains(B2C_PASSWORD_CHANGE)) {
                    logTextView.setText("The user clicks the 'Forgot Password' link in a sign-up or sign-in user flow.\n" +
                            "Your application needs to handle this error code by running a specific user flow that resets the password.");
                    return;
                }

                /* Failed to acquireToken */
                Log.d(TAG, "Authentication failed: " + exception.toString());
                displayError(exception);

                if (exception instanceof MsalClientException) {
                    /* Exception inside MSAL, more info inside MsalError.java */
                } else if (exception instanceof MsalServiceException) {
                    /* Exception when communicating with the STS, likely config issue */
                }
            }

            @Override
            public void onCancel() {
                /* User canceled the authentication */
                Log.d(TAG, "User cancelled login.");
            }
        };
    }

    //
    // Helper methods manage UI updates
    // ================================
    // displayResult() - Display the authentication result.
    // displayError() - Display the token error.
    // updateSignedInUI() - Updates UI when the user is signed in
    // updateSignedOutUI() - Updates UI when app sign out succeeds
    //

    /**
     * Display the graph response
     */
    private void displayResult(@NonNull final IAuthenticationResult result) {
        final String output =
                "Access Token :" + result.getAccessToken() + "\n" +
                        "Scope : " + result.getScope() + "\n" +
                        "Expiry : " + result.getExpiresOn() + "\n" +
                        "Tenant ID : " + result.getTenantId() + "\n";

        logTextView.setText(output);
    }

    /**
     * Display the error message
     */
    private void displayError(@NonNull final Exception exception) {
        logTextView.setText(exception.toString());
    }

    /**
     * Updates UI based on the obtained user list.
     */
    private void updateUI(final List<B2CUser> users) {
        if (users.size() != 0) {
            removeAccountButton.setEnabled(true);
            acquireTokenSilentButton.setEnabled(true);
        } else {
            removeAccountButton.setEnabled(false);
            acquireTokenSilentButton.setEnabled(false);
        }

        final ArrayAdapter<String> dataAdapter = new ArrayAdapter<>(
                getContext(), android.R.layout.simple_spinner_item,
                new ArrayList<String>() {{
                    for (final B2CUser user : users)
                        add(user.getDisplayName());
                }}
        );

        dataAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        b2cUserList.setAdapter(dataAdapter);
        dataAdapter.notifyDataSetChanged();
    }

}

