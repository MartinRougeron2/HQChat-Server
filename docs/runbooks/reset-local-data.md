# Resetting All App Data

This document explains how to reset all data created during development.

## Method 1: Using the App UI (Recommended)

1. Open the app
2. Go to the Profile Selection screen
3. Click the **"Reset All Data"** button (only visible in DEBUG builds)
4. Confirm the action

This will delete:
- ✅ All profiles from SwiftData
- ✅ All friends and messages
- ✅ All keychain items (legacy and profile-based)
- ✅ All UserDefaults (public keys, seeds, username)

## Method 2: Manual Reset via Terminal

If you need to manually reset data, you can delete the following:

### 1. Delete SwiftData Database

```bash
rm ~/Library/Containers/martin.rougeron.DissQus/Data/Library/Application\ Support/default.store
```

### 2. Clear Keychain Items

Open **Keychain Access** app and manually delete:
- `com.dissqus.secretkey` (legacy)
- All items starting with `com.dissqus.profile.` (profile-based keys)

Or use the command line:

```bash
# Delete legacy keychain item
security delete-generic-password -s "com.dissqus.secretkey" 2>/dev/null

# Note: Profile keychain items need to be deleted individually
# You can list them with:
security dump-keychain | grep "com.dissqus.profile"
```

### 3. Clear UserDefaults

```bash
# Remove specific keys
defaults delete martin.rougeron.DissQus com.dissqus.publickey
defaults delete martin.rougeron.DissQus com.dissqus.seed
defaults delete martin.rougeron.DissQus com.dissqus.currentUsername

# Or remove all app preferences (more aggressive)
defaults delete martin.rougeron.DissQus
```

### 4. Complete Reset (Nuclear Option)

To completely remove all app data:

```bash
# Delete the entire app container
rm -rf ~/Library/Containers/martin.rougeron.DissQus

# Clear all keychain items
security delete-generic-password -s "com.dissqus.secretkey" 2>/dev/null

# Clear UserDefaults
defaults delete martin.rougeron.DissQus
```

## Method 3: Programmatic Reset

You can also use the `DataResetService` programmatically:

```swift
import SwiftData

// In your code
let success = DataResetService.resetAllData(
    modelContext: modelContext,
    profileManager: profileManager
)
```

## Data Locations Summary

| Data Type | Location |
|-----------|----------|
| SwiftData Database | `~/Library/Containers/martin.rougeron.DissQus/Data/Library/Application Support/default.store` |
| Keychain (Legacy) | `com.dissqus.secretkey` |
| Keychain (Profiles) | `com.dissqus.profile.{profileId}` |
| UserDefaults | `com.dissqus.publickey`, `com.dissqus.seed`, `com.dissqus.currentUsername` |

## Notes

- The "Reset All Data" button is only available in DEBUG builds (`#if DEBUG`)
- Keychain items with biometric protection will require authentication to delete manually
- After resetting, you'll need to create a new profile to use the app again
- All data deletion is permanent and cannot be undone

