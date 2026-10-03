package df.root;

import android.content.Context;

import java.io.File;

enum RootStrategy {
    UNSUPPORTED(0, false) {
        @Override
        int execute(Context context, IReporter reporter,
                    DirectKernelRegistry.Match directKernel,
                    boolean softReboot) {
            return ExploitRunner.RESULT_UNSUPPORTED;
        }
    },
    MODULE(1, true) {
        @Override
        int execute(Context context, IReporter reporter,
                    DirectKernelRegistry.Match directKernel,
                    boolean softReboot) throws Exception {
            ExploitRunner.stageKsud(context, reporter);
            return withDirtyFragSession(context, reporter,
                    session -> session.runModule(reporter,
                            ExploitRunner.detectKoTarget(reporter), softReboot));
        }
    },
    PATCH_WINDOW(2, false) {
        @Override
        int execute(Context context, IReporter reporter,
                    DirectKernelRegistry.Match directKernel,
                    boolean softReboot) throws Exception {
            File state = new File(context.getFilesDir(), "root-state.txt");
            reporter.report("NEXT: while state=armed, trigger the selected daemon from the host\n");
            return withDirtyFragSession(context, reporter,
                    session -> session.runPatchWindow(reporter,
                            state.getAbsolutePath(), 30000));
        }
    },
    INIT_SHELL(3, true) {
        @Override
        int execute(Context context, IReporter reporter,
                    DirectKernelRegistry.Match directKernel,
                    boolean softReboot) throws Exception {
            return withDirtyFragSession(context, reporter,
                    session -> session.runInitShell(reporter));
        }
    },
    MODULE_INIT(4, true) {
        @Override
        int execute(Context context, IReporter reporter,
                    DirectKernelRegistry.Match directKernel,
                    boolean softReboot) throws Exception {
            return withDirtyFragSession(context, reporter,
                    session -> session.runModule(reporter,
                            ExploitRunner.detectKoTarget(reporter), false));
        }
    },
    DIRECT_KERNEL(5, false) {
        @Override
        int execute(Context context, IReporter reporter,
                    DirectKernelRegistry.Match directKernel,
                    boolean softReboot) throws Exception {
            if (directKernel == null) return ExploitRunner.RESULT_UNSUPPORTED;
            return DirectKernelRunner.run(context, directKernel, reporter);
        }
    };

    final int nativeValue;
    final boolean unattended;

    RootStrategy(int nativeValue, boolean unattended) {
        this.nativeValue = nativeValue;
        this.unattended = unattended;
    }

    abstract int execute(Context context, IReporter reporter,
                         DirectKernelRegistry.Match directKernel,
                         boolean softReboot) throws Exception;

    private interface SessionOperation {
        int run(DirtyFragSession session) throws Exception;
    }

    private static int withDirtyFragSession(Context context, IReporter reporter,
                                            SessionOperation operation) throws Exception {
        try (DirtyFragSession session = DirtyFragSession.open(context, reporter)) {
            return operation.run(session);
        }
    }

    static RootStrategy fromNative(int value) {
        for (RootStrategy strategy : values()) {
            if (strategy.nativeValue == value) return strategy;
        }
        return UNSUPPORTED;
    }
}
