package com.sonicboost.adblocker;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.webkit.JavascriptInterface;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

public class MainActivity extends Activity {
    private static final int REQUEST_VPN = 1001;
    private static final int REQUEST_NOTIFICATIONS = 1002;
    private WebView webView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        webView = new WebView(this);
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setAllowFileAccess(true);
        settings.setAllowContentAccess(false);
        webView.setWebViewClient(new WebViewClient());
        webView.addJavascriptInterface(new WebBridge(), "Android");
        setContentView(webView);
        webView.loadUrl("file:///android_asset/index.html");
    }

    @Override
    protected void onResume() {
        super.onResume();
        syncWebState();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQUEST_VPN) {
            if (resultCode == RESULT_OK) {
                startVpnService();
            } else {
                runJs("window.onVpnPermissionDenied && window.onVpnPermissionDenied();");
            }
        }
    }

    private void requestVpnPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, REQUEST_NOTIFICATIONS);
        }

        Intent permissionIntent = VpnService.prepare(this);
        if (permissionIntent != null) {
            startActivityForResult(permissionIntent, REQUEST_VPN);
        } else {
            startVpnService();
        }
    }

    private void startVpnService() {
        Intent intent = new Intent(this, AdBlockVpnService.class);
        intent.setAction(AdBlockVpnService.ACTION_START);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent);
        } else {
            startService(intent);
        }
        runJs("window.setVpnStateFromNative && window.setVpnStateFromNative(true, "
                + AdBlockVpnService.getBlockedCount() + ");");
    }

    private void stopVpnService() {
        Intent intent = new Intent(this, AdBlockVpnService.class);
        intent.setAction(AdBlockVpnService.ACTION_STOP);
        startService(intent);
        runJs("window.setVpnStateFromNative && window.setVpnStateFromNative(false, "
                + AdBlockVpnService.getBlockedCount() + ");");
    }

    private void syncWebState() {
        if (webView == null) return;
        webView.postDelayed(() -> runJs(
                "window.setVpnStateFromNative && window.setVpnStateFromNative("
                        + AdBlockVpnService.isRunning() + ","
                        + AdBlockVpnService.getBlockedCount() + ");"), 250);
    }

    private void runJs(String script) {
        if (webView == null) return;
        webView.post(() -> webView.evaluateJavascript(script, null));
    }

    @Override
    protected void onDestroy() {
        if (webView != null) {
            webView.removeJavascriptInterface("Android");
            webView.destroy();
            webView = null;
        }
        super.onDestroy();
    }

    public class WebBridge {
        @JavascriptInterface
        public void requestVpn() {
            runOnUiThread(MainActivity.this::requestVpnPermission);
        }

        @JavascriptInterface
        public void stopVpn() {
            runOnUiThread(MainActivity.this::stopVpnService);
        }

        @JavascriptInterface
        public boolean isVpnRunning() {
            return AdBlockVpnService.isRunning();
        }

        @JavascriptInterface
        public long getBlockedCount() {
            return AdBlockVpnService.getBlockedCount();
        }

        @JavascriptInterface
        public void openVpnSettings() {
            runOnUiThread(() -> {
                try {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                        startActivity(new Intent(Settings.ACTION_VPN_SETTINGS));
                    } else {
                        startActivity(new Intent(Settings.ACTION_WIRELESS_SETTINGS));
                    }
                } catch (Exception ignored) {
                    startActivity(new Intent(Settings.ACTION_SETTINGS));
                }
            });
        }
    }
}
