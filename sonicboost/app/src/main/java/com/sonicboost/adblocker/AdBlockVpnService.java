package com.sonicboost.adblocker;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.VpnService;
import android.os.Build;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

public class AdBlockVpnService extends VpnService {
    public static final String ACTION_START = "com.sonicboost.adblocker.START";
    public static final String ACTION_STOP = "com.sonicboost.adblocker.STOP";

    private static final String CHANNEL_ID = "sonicboost_vpn";
    private static final int NOTIFICATION_ID = 2001;
    private static final String VPN_ADDRESS = "10.8.0.1";
    private static final String VPN_DNS = "10.8.0.2";
    private static final String[] UPSTREAM_DNS = {"1.1.1.1", "8.8.8.8"};

    private static final AtomicBoolean RUNNING = new AtomicBoolean(false);
    private static final AtomicLong BLOCKED_COUNT = new AtomicLong(0);

    private final Set<String> blockedDomains = new HashSet<>();
    private volatile boolean shouldRun;
    private ParcelFileDescriptor vpnInterface;
    private Thread workerThread;

    public static boolean isRunning() {
        return RUNNING.get();
    }

    public static long getBlockedCount() {
        return BLOCKED_COUNT.get();
    }

    @Override
    public void onCreate() {
        super.onCreate();
        loadBlocklist();
        BLOCKED_COUNT.set(getSharedPreferences("stats", MODE_PRIVATE).getLong("blocked", 0));
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent != null ? intent.getAction() : ACTION_START;
        if (ACTION_STOP.equals(action)) {
            shutdownVpn();
            stopSelf();
            return START_NOT_STICKY;
        }

        startAsForeground();
        if (workerThread == null || !workerThread.isAlive()) {
            shouldRun = true;
            workerThread = new Thread(this::runVpnLoop, "SonicBoost-DNS-VPN");
            workerThread.start();
        }
        return START_STICKY;
    }

    private void runVpnLoop() {
        try {
            Builder builder = new Builder()
                    .setSession("SonicBoost AdBlock")
                    .setMtu(1500)
                    .addAddress(VPN_ADDRESS, 32)
                    .addDnsServer(VPN_DNS)
                    .addRoute(VPN_DNS, 32);

            vpnInterface = builder.establish();
            if (vpnInterface == null) {
                RUNNING.set(false);
                stopSelf();
                return;
            }

            RUNNING.set(true);
            FileInputStream input = new FileInputStream(vpnInterface.getFileDescriptor());
            FileOutputStream output = new FileOutputStream(vpnInterface.getFileDescriptor());
            byte[] packetBuffer = new byte[32767];

            while (shouldRun) {
                int length = input.read(packetBuffer);
                if (length <= 0) continue;

                DnsRequest request = parseDnsRequest(packetBuffer, length);
                if (request == null) continue;

                String domain = parseDomain(request.dnsPayload);
                byte[] dnsResponse;
                if (domain != null && isBlocked(domain)) {
                    dnsResponse = buildNxDomainResponse(request.dnsPayload);
                    long count = BLOCKED_COUNT.incrementAndGet();
                    getSharedPreferences("stats", MODE_PRIVATE).edit().putLong("blocked", count).apply();
                    if (count % 10 == 0) updateNotification();
                } else {
                    dnsResponse = queryUpstream(request.dnsPayload);
                }

                if (dnsResponse != null) {
                    byte[] responsePacket = buildIpv4UdpResponse(request, dnsResponse);
                    output.write(responsePacket);
                    output.flush();
                }
            }
        } catch (IOException ignored) {
            // Closing the VPN descriptor during shutdown naturally breaks the blocking read().
        } catch (Exception ignored) {
        } finally {
            RUNNING.set(false);
            closeInterface();
            workerThread = null;
            if (shouldRun) {
                shouldRun = false;
                stopForeground(true);
                stopSelf();
            }
        }
    }

    private DnsRequest parseDnsRequest(byte[] packet, int length) {
        if (length < 28) return null;
        int version = (packet[0] >> 4) & 0x0F;
        if (version != 4) return null;

        int ihl = (packet[0] & 0x0F) * 4;
        if (ihl < 20 || length < ihl + 8) return null;
        int protocol = packet[9] & 0xFF;
        if (protocol != 17) return null;

        int totalLength = readUnsignedShort(packet, 2);
        if (totalLength <= 0 || totalLength > length) totalLength = length;

        int srcPort = readUnsignedShort(packet, ihl);
        int dstPort = readUnsignedShort(packet, ihl + 2);
        if (dstPort != 53) return null;

        int dnsOffset = ihl + 8;
        int dnsLength = totalLength - dnsOffset;
        if (dnsLength < 12 || dnsOffset + dnsLength > length) return null;

        byte[] srcIp = new byte[4];
        byte[] dstIp = new byte[4];
        System.arraycopy(packet, 12, srcIp, 0, 4);
        System.arraycopy(packet, 16, dstIp, 0, 4);

        byte[] dnsPayload = new byte[dnsLength];
        System.arraycopy(packet, dnsOffset, dnsPayload, 0, dnsLength);
        return new DnsRequest(srcIp, dstIp, srcPort, dstPort, dnsPayload);
    }

    private String parseDomain(byte[] dns) {
        if (dns == null || dns.length < 13) return null;
        StringBuilder domain = new StringBuilder();
        int index = 12;
        int labels = 0;

        while (index < dns.length && labels < 128) {
            int labelLength = dns[index] & 0xFF;
            if (labelLength == 0) break;
            if ((labelLength & 0xC0) == 0xC0) return null;
            index++;
            if (labelLength > 63 || index + labelLength > dns.length) return null;
            if (domain.length() > 0) domain.append('.');
            domain.append(new String(dns, index, labelLength, StandardCharsets.US_ASCII));
            index += labelLength;
            labels++;
        }

        return domain.length() == 0 ? null : domain.toString().toLowerCase(Locale.ROOT);
    }

    private boolean isBlocked(String domain) {
        String current = domain.toLowerCase(Locale.ROOT);
        while (!current.isEmpty()) {
            if (blockedDomains.contains(current)) return true;
            int dot = current.indexOf('.');
            if (dot < 0) break;
            current = current.substring(dot + 1);
        }
        return false;
    }

    private byte[] queryUpstream(byte[] query) {
        for (String server : UPSTREAM_DNS) {
            try (DatagramSocket socket = new DatagramSocket()) {
                if (!protect(socket)) continue;
                socket.setSoTimeout(2500);
                InetAddress address = InetAddress.getByName(server);
                DatagramPacket request = new DatagramPacket(query, query.length, address, 53);
                socket.send(request);

                byte[] buffer = new byte[4096];
                DatagramPacket response = new DatagramPacket(buffer, buffer.length);
                socket.receive(response);

                byte[] result = new byte[response.getLength()];
                System.arraycopy(response.getData(), response.getOffset(), result, 0, response.getLength());
                return result;
            } catch (SocketTimeoutException ignored) {
            } catch (Exception ignored) {
            }
        }
        return buildServerFailureResponse(query);
    }

    private byte[] buildNxDomainResponse(byte[] query) {
        byte[] response = query.clone();
        if (response.length < 12) return response;
        response[2] = (byte) (0x80 | (query[2] & 0x01));
        response[3] = (byte) 0x83;
        response[6] = 0;
        response[7] = 0;
        response[8] = 0;
        response[9] = 0;
        response[10] = 0;
        response[11] = 0;
        return response;
    }

    private byte[] buildServerFailureResponse(byte[] query) {
        byte[] response = query.clone();
        if (response.length < 12) return response;
        response[2] = (byte) (0x80 | (query[2] & 0x01));
        response[3] = (byte) 0x82;
        response[6] = 0;
        response[7] = 0;
        response[8] = 0;
        response[9] = 0;
        response[10] = 0;
        response[11] = 0;
        return response;
    }

    private byte[] buildIpv4UdpResponse(DnsRequest request, byte[] dnsResponse) {
        int totalLength = 20 + 8 + dnsResponse.length;
        byte[] packet = new byte[totalLength];

        packet[0] = 0x45;
        packet[1] = 0;
        writeUnsignedShort(packet, 2, totalLength);
        writeUnsignedShort(packet, 4, 0);
        writeUnsignedShort(packet, 6, 0x4000);
        packet[8] = 64;
        packet[9] = 17;
        packet[10] = 0;
        packet[11] = 0;
        System.arraycopy(request.dstIp, 0, packet, 12, 4);
        System.arraycopy(request.srcIp, 0, packet, 16, 4);
        int ipChecksum = checksum(packet, 0, 20);
        writeUnsignedShort(packet, 10, ipChecksum);

        writeUnsignedShort(packet, 20, request.dstPort);
        writeUnsignedShort(packet, 22, request.srcPort);
        writeUnsignedShort(packet, 24, 8 + dnsResponse.length);
        writeUnsignedShort(packet, 26, 0);
        System.arraycopy(dnsResponse, 0, packet, 28, dnsResponse.length);
        return packet;
    }

    private int checksum(byte[] data, int offset, int length) {
        long sum = 0;
        int i = offset;
        while (length > 1) {
            sum += ((data[i] & 0xFF) << 8) | (data[i + 1] & 0xFF);
            i += 2;
            length -= 2;
        }
        if (length > 0) sum += (data[i] & 0xFF) << 8;
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return (int) (~sum) & 0xFFFF;
    }

    private int readUnsignedShort(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    private void writeUnsignedShort(byte[] data, int offset, int value) {
        data[offset] = (byte) ((value >> 8) & 0xFF);
        data[offset + 1] = (byte) (value & 0xFF);
    }

    private void loadBlocklist() {
        blockedDomains.clear();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(getAssets().open("blocklist.txt"), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim().toLowerCase(Locale.ROOT);
                if (line.isEmpty() || line.startsWith("#")) continue;
                blockedDomains.add(line);
            }
        } catch (IOException ignored) {
        }
    }

    private void startAsForeground() {
        NotificationManager manager = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID,
                    "Proteção SonicBoost",
                    NotificationManager.IMPORTANCE_LOW);
            channel.setDescription("Mostra quando o bloqueio DNS local está ativo");
            manager.createNotificationChannel(channel);
        }

        Notification notification = buildNotification();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(NOTIFICATION_ID, notification);
        }
    }

    private Notification buildNotification() {
        Intent openIntent = new Intent(this, MainActivity.class);
        PendingIntent contentIntent = PendingIntent.getActivity(
                this, 0, openIntent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        Intent stopIntent = new Intent(this, AdBlockVpnService.class);
        stopIntent.setAction(ACTION_STOP);
        PendingIntent stopPendingIntent = PendingIntent.getService(
                this, 1, stopIntent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        Notification.Builder builder = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                ? new Notification.Builder(this, CHANNEL_ID)
                : new Notification.Builder(this);

        return builder
                .setContentTitle("SonicBoost AdBlock ativo")
                .setContentText(BLOCKED_COUNT.get() + " consultas de anúncios bloqueadas")
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setContentIntent(contentIntent)
                .setOngoing(true)
                .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Desativar", stopPendingIntent)
                .build();
    }

    private void updateNotification() {
        NotificationManager manager = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        manager.notify(NOTIFICATION_ID, buildNotification());
    }

    private synchronized void shutdownVpn() {
        shouldRun = false;
        RUNNING.set(false);
        closeInterface();
        if (workerThread != null) {
            workerThread.interrupt();
            workerThread = null;
        }
        stopForeground(true);
    }

    private synchronized void closeInterface() {
        if (vpnInterface != null) {
            try {
                vpnInterface.close();
            } catch (IOException ignored) {
            }
            vpnInterface = null;
        }
    }

    @Override
    public void onRevoke() {
        shutdownVpn();
        stopSelf();
        super.onRevoke();
    }

    @Override
    public void onDestroy() {
        shutdownVpn();
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return super.onBind(intent);
    }

    private static class DnsRequest {
        final byte[] srcIp;
        final byte[] dstIp;
        final int srcPort;
        final int dstPort;
        final byte[] dnsPayload;

        DnsRequest(byte[] srcIp, byte[] dstIp, int srcPort, int dstPort, byte[] dnsPayload) {
            this.srcIp = srcIp;
            this.dstIp = dstIp;
            this.srcPort = srcPort;
            this.dstPort = dstPort;
            this.dnsPayload = dnsPayload;
        }
    }
}
