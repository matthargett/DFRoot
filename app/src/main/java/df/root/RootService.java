package df.root;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.IBinder;
import android.os.PowerManager;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;

public final class RootService extends Service implements IReporter {
    private static final String TAG = "dfroot";
    private static final String CHANNEL = "root-operation";
    private static final int NOTIFICATION = 1701;
    static final String EXTRA_UNATTENDED_ONLY = "df.root.extra.UNATTENDED_ONLY";
    static final String EXTRA_SOFT_REBOOT = "df.root.extra.SOFT_REBOOT";
    static final String EXTRA_PROBE_ONLY = "df.root.extra.PROBE_ONLY";
    static final String LAST_OPERATION_LOG = "last-operation.log";

    private final AtomicBoolean running = new AtomicBoolean(false);
    private final Object reportLock = new Object();
    private FileOutputStream reportFile;

    @Override
    public void onCreate() {
        super.onCreate();
        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager != null) {
            manager.createNotificationChannel(new NotificationChannel(
                    CHANNEL, "Root operation", NotificationManager.IMPORTANCE_LOW));
        }
        Notification notification = new Notification.Builder(this, CHANNEL)
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setContentTitle("DFRoot active")
                .setContentText("Patch restoration watchdog is running")
                .setOngoing(true)
                .build();
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION, notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(NOTIFICATION, notification);
        }
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (!running.compareAndSet(false, true)) {
            Log.i(TAG, "root service already active; ignoring duplicate start");
            return START_NOT_STICKY;
        }
        boolean unattendedOnly = intent != null
                && intent.getBooleanExtra(EXTRA_UNATTENDED_ONLY, false);
        boolean softReboot = intent != null
                && intent.getBooleanExtra(EXTRA_SOFT_REBOOT, false);
        boolean probeOnly = intent != null
                && intent.getBooleanExtra(EXTRA_PROBE_ONLY, false);
        openReportFile(probeOnly ? "probe" : unattendedOnly ? "unattended" : "interactive");
        PowerManager manager = getSystemService(PowerManager.class);
        PowerManager.WakeLock wakeLock = manager == null ? null
                : manager.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK,
                                      "dfroot:operation");
        if (wakeLock != null) wakeLock.acquire(600000);
        new Thread(() -> {
            try {
                Context storage = createDeviceProtectedStorageContext();
                int rc = probeOnly
                        ? ExploitRunner.probe(storage, this)
                        : unattendedOnly
                            ? ExploitRunner.runUnattended(storage, this, softReboot)
                            : ExploitRunner.run(storage, this, softReboot);
                report("root service result=" + rc + "\n");
            } catch (Exception e) {
                Log.e(TAG, "root service exception", e);
                report("root service exception=" + Log.getStackTraceString(e) + "\n");
            } finally {
                if (wakeLock != null && wakeLock.isHeld()) wakeLock.release();
                running.set(false);
                stopForeground(STOP_FOREGROUND_REMOVE);
                stopSelf();
            }
        }, "dfroot-operation").start();
        return START_NOT_STICKY;
    }

    @Override
    public void report(String message) {
        Log.i(TAG, message.trim());
        synchronized (reportLock) {
            if (reportFile == null) return;
            try {
                reportFile.write(message.getBytes(StandardCharsets.UTF_8));
                reportFile.flush();
            } catch (IOException error) {
                Log.e(TAG, "operation log write failed", error);
                closeReportFileLocked();
            }
        }
    }

    @Override
    public void onDestroy() {
        synchronized (reportLock) {
            closeReportFileLocked();
        }
        super.onDestroy();
    }

    private void openReportFile(String mode) {
        Context storage = createDeviceProtectedStorageContext();
        File path = new File(storage.getFilesDir(), LAST_OPERATION_LOG);
        synchronized (reportLock) {
            closeReportFileLocked();
            try {
                reportFile = new FileOutputStream(path, false);
                reportFile.write(("operation=" + mode + " start_ms="
                        + System.currentTimeMillis() + "\n")
                        .getBytes(StandardCharsets.UTF_8));
                reportFile.flush();
                Log.i(TAG, "operation log=" + path);
            } catch (IOException error) {
                reportFile = null;
                Log.e(TAG, "operation log open failed path=" + path, error);
            }
        }
    }

    private void closeReportFileLocked() {
        if (reportFile == null) return;
        try {
            reportFile.close();
        } catch (IOException error) {
            Log.e(TAG, "operation log close failed", error);
        } finally {
            reportFile = null;
        }
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
