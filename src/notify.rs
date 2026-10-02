// Notifications attributed to "dott" on macOS. macOS credits notifications to the posting app's
// bundle, so dott keeps a tiny ~/.dott/dott.app holding a copy of this binary, runs
// that executable with --notify, and that copy posts via NSUserNotificationCenter.
use std::{fs, io, path::Path, process::Command, time::Duration};

pub const BUNDLE_ID: &str = "com.yodatosh.dott.notifier";

fn info_plist() -> String {
    format!(r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key><string>dott</string>
    <key>CFBundleIdentifier</key><string>{BUNDLE_ID}</string>
    <key>CFBundleName</key><string>dott</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>LSUIElement</key><true/>
    <key>NSUserNotificationAlertStyle</key><string>banner</string>
</dict>
</plist>
"#)
}

// Writes the bundle, or repoints it when dott moved (e.g. a new install location).
// Returns true when the bundle didn't exist before.
fn ensure_bundle(app: &Path, binary: &Path) -> io::Result<bool> {
    let created = !app.exists();
    let macos = app.join("Contents").join("MacOS");
    fs::create_dir_all(&macos)?;
    let plist = app.join("Contents").join("Info.plist");
    if fs::read_to_string(&plist).ok() != Some(info_plist()) {
        fs::write(&plist, info_plist())?;
    }
    // A real copy, not a symlink: macOS resolves links and would register the bare binary, which
    // System Settings can't list. Refreshed whenever dott is updated.
    let executable = macos.join("dott");
    let current = fs::symlink_metadata(&executable).ok().filter(|m| m.file_type().is_file());
    let stale = match (&current, fs::metadata(binary)) {
        (Some(copy), Ok(source)) => copy.len() != source.len()
            || source.modified().ok() > copy.modified().ok(),
        (None, _) => true,
        (Some(_), Err(error)) => return Err(error),
    };
    if stale {
        let temporary = macos.join(format!(".dott-{}.tmp", std::process::id()));
        let result = fs::copy(binary, &temporary).and_then(|_| fs::rename(&temporary, &executable));
        let _ = fs::remove_file(&temporary);
        result?;
    }
    Ok(created)
}

/// Creates or repairs ~/.dott/dott.app; true when it was just created.
pub fn ensure(dott_dir: &Path, binary: &Path) -> io::Result<bool> {
    ensure_bundle(&dott_dir.join("dott.app"), binary)
}

/// Posts through dott.app. An error means the caller should fall back to another method.
pub fn send(dott_dir: &Path, binary: &Path, title: &str, body: &str) -> Result<(), String> {
    let app = dott_dir.join("dott.app");
    ensure_bundle(&app, binary).map_err(|e| format!("Could not create {}: {e}", app.display()))?;
    // Running the executable by its in-bundle path gives it dott.app's identity.
    let output = Command::new(app.join("Contents/MacOS/dott")).arg("--notify").arg(title).arg(body)
        .output().map_err(|e| e.to_string())?;
    if output.status.success() { Ok(()) } else { Err(String::from_utf8_lossy(&output.stderr).trim().to_string()) }
}

/// Runs inside dott.app (the --notify mode).
#[allow(deprecated)] // NSUserNotification still works for bundles without a developer signature.
pub fn deliver(title: &str, body: &str) -> Result<(), String> {
    use objc2_foundation::{NSBundle, NSString, NSUserNotification, NSUserNotificationCenter};
    // Outside a bundle the notification center is nil, so check before touching it.
    if NSBundle::mainBundle().bundleIdentifier().is_none_or(|id| id.to_string() != BUNDLE_ID) {
        return Err("--notify only works inside dott.app".into());
    }
    let notification = NSUserNotification::new();
    notification.setTitle(Some(&NSString::from_str(title)));
    notification.setInformativeText(Some(&NSString::from_str(body)));
    NSUserNotificationCenter::defaultUserNotificationCenter().deliverNotification(&notification);
    // Delivery is handed to the notification daemon asynchronously; don't exit before it lands.
    std::thread::sleep(Duration::from_millis(500));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_is_created_and_follows_the_binary() {
        let dir = std::env::temp_dir().join(format!("dott-notify-test-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let app = dir.join("dott.app");
        let binary = dir.join("dott-binary");
        fs::create_dir_all(&dir).unwrap();
        fs::write(&binary, b"v1").unwrap();
        assert!(ensure_bundle(&app, &binary).unwrap());
        let plist = fs::read_to_string(app.join("Contents/Info.plist")).unwrap();
        assert!(plist.contains(BUNDLE_ID) && plist.contains("<key>LSUIElement</key><true/>"));
        let executable = app.join("Contents/MacOS/dott");
        assert!(fs::symlink_metadata(&executable).unwrap().file_type().is_file(), "a copy, not a link");
        assert_eq!(fs::read(&executable).unwrap(), b"v1");
        // An update replaces the binary; the copy follows.
        std::thread::sleep(Duration::from_millis(20));
        fs::write(&binary, b"v2 longer").unwrap();
        assert!(!ensure_bundle(&app, &binary).unwrap());
        assert_eq!(fs::read(&executable).unwrap(), b"v2 longer");
        // Bundles from the earlier symlink layout are replaced with a copy.
        fs::remove_file(&executable).unwrap();
        std::os::unix::fs::symlink(&binary, &executable).unwrap();
        ensure_bundle(&app, &binary).unwrap();
        assert!(fs::symlink_metadata(&executable).unwrap().file_type().is_file());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn notify_mode_refuses_to_run_outside_the_bundle() {
        assert!(deliver("title", "body").is_err());
    }
}
